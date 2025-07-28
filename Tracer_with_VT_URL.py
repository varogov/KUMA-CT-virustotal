#!/usr/bin/python3
#2Rog

import socket
from select import select
from sys import platform
from re import match
from datetime import datetime
from dateutil.relativedelta import relativedelta
from urllib.parse import unquote
import requests
import base64

SERVER = "0.0.0.0" #ip address listening
PORT = 16666 #listening port
regexURLFeed = r"\S+?\n?\S+\|url\=([^\|]+).+"
ADDR = (SERVER, PORT)

class CtrlBreakInterrupt(BaseException):
    pass

def handler(*args):
    raise CtrlBreakInterrupt

def all_sockets_closed(server_socket, starttime):
    print("\n\nAll Clients Disconnected\nClosing The Server...")
    endtime = datetime.now()
    diff = relativedelta(endtime, starttime)
    elapsed = "{} year {} month {} days {} hours {} minutes {} seconds {} microseconds".format(diff.years, diff.months, diff.days, diff.hours, diff.minutes, diff.seconds, diff.microseconds)
    server_socket.close()
    print(f"\nThe Server Was Active For: {elapsed}\n\n")

def active_client_sockets(connected_sockets):
    print("\nCurrently Connected Sockets:")
    for c in connected_sockets:
        print("\t", c.getpeername())

def serve_client(current_socket, server_socket, connected_sockets, starttime):
    try:
        client_data = current_socket.recv(1024).decode()
        date_time = datetime.now()

        if client_data != "":
            print(
                f"\nReceived new message form client {current_socket.getpeername()} at {date_time}:"
            )

    except ConnectionResetError:
        print(f"\nThe client {current_socket.getpeername()} has disconnected...")
        connected_sockets.remove(current_socket)
        current_socket.close()
        if len(connected_sockets) != 0:
            active_client_sockets(connected_sockets)
        else:
            raise ValueError

    else:
        if client_data != "":
            print(client_data)

        if match(regexURLFeed, client_data):
            Category = "VT_URL_Status"
            ioc = match(regexURLFeed, str(client_data)).group(1)
            decoded_url = unquote(ioc)

            VT_API_KEY = ""  #<- your API-Key VirusTotal
            url_id = base64.urlsafe_b64encode(decoded_url.encode()).decode().strip("=")
            headers = {"x-apikey": VT_API_KEY}

            try:
                vt_response = requests.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}",
                    headers=headers,
                    timeout=10
                )

                if vt_response.status_code == 200:
                    vt_json = vt_response.json()
                    attributes = vt_json['data']['attributes']
                    stats = attributes.get('last_analysis_stats', {})
                    malicious = stats.get('malicious', 0)
                    total = sum(stats.values())

                    malicious_engines = [
                        engine
                        for engine, result in attributes.get('last_analysis_results', {}).items()
                        if result.get('category') == 'malicious'
                    ]
                    engine_list = ",".join(malicious_engines) or "None"

                    results_raw = attributes.get("last_analysis_results", {})

                    result_values = set()
                    for res in results_raw.values():
                      if isinstance(res, dict):
                        val = res.get("result")
                        if val not in ("clean", "unrated", None):
                          result_values.add(val)

                    result_types_str = ",".join(sorted(result_values)) or "None"

                    categories = attributes.get('categories', 0)
                    scan_date = attributes.get('last_analysis_date', 0)
                    scan_date_str = datetime.utcfromtimestamp(scan_date).strftime('%Y-%m-%d') if scan_date else "N/A"

                    vt_result = f"{malicious}/{total} malicious"
                else:
                    vt_result = f"VT API error: {vt_response.status_code}"
                    engine_list = "N/A"
                    scan_date_str = "N/A"

            except Exception as e:
                vt_result = f"VT Exception: {str(e)}"
                engine_list = "N/A"
                scan_date_str = "N/A"

            responseToKUMA = (
                f"Category={Category}"
                f"|MatchedIndicator={ioc}"
                f"|decodedURL={decoded_url}"
                f"|VT_Result={vt_result}"
                f"|Engines={engine_list}"
                f"|ResultTypes={result_types_str}"
                f"|Categories_info={categories}"
                f"|ScanDate={scan_date_str}\nLookupFinished"
            )

            current_socket.send(responseToKUMA.encode())
            print("Responded by: " + responseToKUMA)

            connected_sockets.remove(current_socket)
            current_socket.close()

        if not client_data:
            connected_sockets.remove(current_socket)
            current_socket.close()

def main():
    print("Setting up server...")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if platform != 'win32':
        server_socket.setsockopt(socket.SOL_TCP, 23, 5)
    server_socket.bind(ADDR)
    server_socket.listen()

    print("\n* Server is ON *\n")
    print("Waiting for clients to establish connection...")
    starttime = datetime.now()
    connected_sockets = []
    try:
        while True:
            ready_to_read, ready_to_write, in_error = select(
                [server_socket] + connected_sockets, [], []
            )
            for current_socket in ready_to_read:
                if current_socket is server_socket:
                    (client_socket, client_address) = current_socket.accept()
                    print("\nNew client joined!", client_address)
                    connected_sockets.append(client_socket)
                    active_client_sockets(connected_sockets)
                    continue
                serve_client(
                    current_socket, server_socket, connected_sockets, starttime
                )
    except ValueError:
        all_sockets_closed(server_socket, starttime)
    except CtrlBreakInterrupt:
        print("\nCTRL-BREAK Entered")
    except KeyboardInterrupt:
        print("\nCTRL-C Entered")
        all_sockets_closed(server_socket, starttime)

if __name__ == "__main__":
    main()
