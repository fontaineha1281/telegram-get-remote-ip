# Telegram get remote IP

## New 2024 version written in python, against bash.

This script is intended to be used to determine the IP address of the interlocutor in the telegram messenger. 
You must have tshark installed to use it.

Working on **MacOS**, **Linux** and **Windows**.

Thx [@WonderMr](https://github.com/WonderMr) for adding Windows support and other improovements.

TechCrunch wrote about the utility — [Telegram is still leaking user IP addresses to contacts](https://techcrunch.com/2023/10/19/telegram-is-still-leaking-user-ip-addresses-to-contacts/)

***Attention! To determine the IP address, you must be in each other's contacts.***

<!-- ![Get caller IP](https://i.imgur.com/thW5I0x.png) -->
## How to use?

1. Install [Telegram desktop](https://desktop.telegram.org/) client on Linux or Mac.
2. Install tshark (**sudo apt install tshark** or download for macOS [here](https://www.wireshark.org/download.html), it's comes with wireshark).
3. Run script, call and wait for an answer.
4. Profit! You have received the IP address of the interlocutor.

### Get & Run (Ubuntu 20 example)

```sh
$ sudo apt update
$ sudo apt install -y python3-pip python3-venv tshark
$ git clone https://github.com/fontaineha1281/telegram-get-remote-ip
$ cd telegram-get-remote-ip
$ python3 -m venv venv
$ source ./venv/bin/activate
$ sudo pip3 install -r requirements.txt
$ sudo python3 tg_get_ip.py
```

Or specify the interface immediately at startup:

```sh
$ sudo python3 -i en0 tg_get_ip.py
```

**PS.** Possible work with termux on android smartphones. Root authority is required to capture traffic.

