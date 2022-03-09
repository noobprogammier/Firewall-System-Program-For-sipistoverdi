class exception_related():
	def __init__(self, objecttarg:str, types:str) -> str:
		if types == "arguments":
			items = [bob for bob in ["entries", "cookies"] if bob == objecttarg]
			if len(items) != 1:
				raise firewallDB.exc("\r\x0A[PATHFW.EXCEPTION] Invalid speciment.")
class firewallDB(Exception, exception_related):
	class exc(Exception):
		pass 
	def __init__(self, ipv4:str, author:list, ban=True, tor="entries"):
		self.host = ipv4
		self.rules = []
		self.path = ""
		self.sockx = None
		self.authorised = author
		self.type_of_rule = tor
		self.cookie_enumerated = []
		self.key_ = b""
		self.path = ""
		self.bprir = None
		self.payload = b""
		exception_related(objecttarg=self.type_of_rule, types="arguments").__init__
	@property
	def entry(self):
		rule = self.rules
		just_inload = [bob for bob in open("d:/sipistoverdi/docs/security_modules/firewall_rules/entries.dbf", "r") if self.host in bob]
		if len(just_inload) != 0:
			return
		from json import loads, dumps
		rules_ = {}
		for count, items in enumerate(self.rules[0]):
			rules_[count] = self.rules[0][items]
		json_text = dumps({"ipv4":self.host,"path":rules_})
		inherit = "".join(bob for bob in open("d:/sipistoverdi/docs/security_modules/firewall_rules/entries.dbf", "r"))
		if len(inherit) == 0 or inherit == "":
			inherit = "{}"
		loaded = loads(inherit)
		loaded[self.host] = loads(json_text)
		from os import remove
		vr = open("d:/sipistoverdi/docs/security_modules/firewall_rules/entries.dbf", "w")
		vr.write(" ")
		vr.close()
		open("d:/sipistoverdi/docs/security_modules/firewall_rules/entries.dbf", "a").write(dumps(loaded))
	def if_exists(self):
		rope = [bob for bob in open("d:/sipistoverdi/docs/security_modules/firewall_rules/entries.dbf", "r") if self.host in bob]
		if len(rope) != 0:
			return True
		return None
	def CheckIf(self):
		rope = [bob for bob in open("d:/sipistoverdi/docs/security_modules/firewall_rules/cookie_keeper.dbf", "r") if self.host in bob]
		if len(rope) != 0:
			return True
		return None
	@property
	def read_edit(self):
		from json import loads, dumps
		whole = "".join(bob for bob in open("d:/sipistoverdi/docs/security_modules/firewall_rules/entries.dbf", "r"))
		rep = loads(whole)
		rep[self.host]["rule"] = self.rules[1]
		rules_ = {}
		for count, items in enumerate(self.rules[0]):
			rules_[count] = self.rules_[0][items]
		rep[self.host]["path"] = rules_
		open("d:/sipistoverdi/docs/security_modules/firewall_rules/entries.dbf", "w").write("")
		open("d:/sipistoverdi/docs/security_modules/firewall_rules/entries.dbf", "a").write(dumps(rep))
		return
	@property
	def entry_Log(self):
		from datetime import datetime, date
		from json import loads, dumps
		rx = "".join(bob for bob in open("d:/sipistoverdi/docs/security_modules/firewall_rules/logs.txt", "r"))
		if len(rx) == 0:
			rx = "{}"
		rp = loads(rx)
		seperated = date(datetime.now().year, datetime.now().month, datetime.now().day)
		packs = {"weeks":{1:"Mon", 2:"Tue", 3:"Wed", 4:"Tur", 5:"Fri", 6:"Sat", 7:"Sun"}, "months":{1:"Jan", 2:"Feb", 3:"Mar", 4:"April", 5:"May", 6:"Jun", 7:"Jul", 8:"Aug", 9:"Sep", 10:"Oct", 11:"Nov", 12:"Dec"}};
		rp["%s"%(self.host)] = {"Time-Entered":"%s, %s %s %s:%s:%s"%(packs["weeks"][seperated.isocalendar()[2]], packs["months"][datetime.now().month], datetime.now().year, datetime.now().hour, datetime.now().minute, datetime.now().second)}
		br = open("d:/sipistoverdi/docs/security_modules/firewall_rules/logs.txt", "w")
		br.write(dumps(rp))
		return
	@property
	def entry_payloads(self):
		from os import listdir, mkdir
		from os.path import exists
		from datetime import datetime
		from json import loads, dumps
		from base64 import b64encode
		from Cryptodome.Cipher import AES
		asr = "%s%s%s"%(datetime.now().year, datetime.now().month, datetime.now().day)
		try:
			if exists("d:/sipistoverdi/docs/security_modules/firewall_rules/hosts_payloads/%s"%(self.host)) == False:
				mkdir("d:/sipistoverdi/docs/security_modules/firewall_rules/hosts_payloads/%s"%(self.host))
		except:
			pass 
		if exists("d:/sipistoverdi/docs/security_modules/firewall_rules/hosts_payloads/%s/%s"%(self.host, asr)) == False:
			mkdir("d:/sipistoverdi/docs/security_modules/firewall_rules/hosts_payloads/%s/%s"%(self.host, asr))
		op_ = open("d:/sipistoverdi/docs/security_modules/firewall_rules/hosts_payloads/%s/%s/hour_minute_second_%s_%s_%s.dbf"%(self.host, asr, datetime.now().hour, datetime.now().minute, datetime.now().second), "a")
		read_file = "".join(bob for bob in open("d:/sipistoverdi/docs/security_modules/firewall_rules/hosts_payloads/%s/%s/hour_minute_second_%s_%s_%s.dbf"%(self.host, asr, datetime.now().hour, datetime.now().minute, datetime.now().second), "r", encoding="utf-8", errors="ignore"))
		if len(read_file) != 0:
			rope = loads(read_file)
		else:
			rope = {}
		rope[self.host] = {"Payload":b64encode(self.payload).decode("utf-8"), "Length":len(self.payload)}
		open("d:/sipistoverdi/docs/security_modules/firewall_rules/hosts_payloads/%s/%s/hour_minute_second_%s_%s_%s.dbf"%(self.host, asr, datetime.now().hour, datetime.now().minute, datetime.now().second), "w").write(" ")
		op_.write(dumps(rope))
		op_.close()
		return
	@entry_payloads.setter
	def set_payload(self, newval:bytes) -> bytes:
		self.payload = newval
	@entry_payloads.setter
	def set_key(self, newval:bytes) -> bytes:
		self.key_ = newval
	@property
	def entry_cookieDB(self):
		from Cryptodome.Cipher import AES
		from base64 import b64encode
		from json import loads, dumps
		from hashlib import md5
		canteen = {}
		for count, objitem in enumerate(self.cookie_enumerated, 1):
			canteen[count] = objitem
		attr = [open("d:/sipistoverdi/docs/security_modules/firewall_rules/cookie_keeper.dbf", "a"), open("d:/sipistoverdi/docs/security_modules/firewall_rules/cookie_keeper.dbf", "r", encoding="utf-8")]
		modulus = b64encode(AES.new(self.key_, AES.MODE_GCM, self.key_).encrypt(b64encode(dumps(canteen).encode("utf-8"))))
		ideq = "".join(bob for bob in attr[1])
		if len(ideq) == 0:
			ideq = "{}"
		tupak = loads(ideq)
		gather = [item for item in tupak if self.host == item]
		if len(gather) != 0:
			return
		rp = md5()
		rp.update(modulus)
		tupak[self.host] = {"Cookies":modulus.decode("utf-8"), "LengthofB64":len(modulus), "HASH-MD5 (PART DATA)":rp.hexdigest()[:9]}
		aters = attr[0]
		nov_file = open("d:/sipistoverdi/docs/security_modules/firewall_rules/cookie_keeper.dbf", "w").write(" ")
		aters.write(dumps(tupak))
		aters.close()
		return None
	@entry_cookieDB.setter
	def set_cookies(self, newval:list):
		if isinstance(newval, list) == False:
			raise firewallDB.exc("\r\x0A[PATHFW.EXCEPTION] x item is not a list. . .")
		self.cookie_enumerated = newval
	@entry.setter
	def set_priority(self, newval:bool):
		self.bprir = newval
	@entry_cookieDB.setter
	def set_key(self, newval:bytes) -> bytes:
		self.key_ = newval
	@entry.setter
	def set_path(self, newval:str):
		self.path = newval
	@entry.setter
	def set_rule(self, rule:list):
		self.rules = rule
	@read_edit.setter
	def set_rule(self, rule:list):
		self.rules = rule
	@property
	def CheckHost(self):
		from docs.reqpayloads import create_header
		from json import loads 
		loads = loads("".join(bob for bob in open("d:/sipistoverdi/docs/security_modules/firewall_rules/entries.dbf", "r")))
		if self.host in loads:
			load = loads[self.host]
			path = [load["path"][bob] for bob in load["path"]]
			if path[0] == "1":
				path = [""]
			least = [bob for bob in load["path"]]
			dictionary_object = []
			for items in path:
				if isinstance(items, dict):
					dictionary_object.append(items)
			if "*" in dictionary_object[0]:
				if dictionary_object[0]["*"] == "DENY":
					apt = create_header(location=self.path, status_code=["403", "default"], connection="close", httpver="HTTP/1.1")
					apt.set_server = "sipistoverdi"
					apt.set_compatible = "IE=edge"
					apt.accept_ch = "Viewport-Width, Width"
					apt.xss_protection = "0"
					apt.setit(object=b"403 Forbidden (file to be fixed, better design. To do).")
					self.sockx.send(apt.app)
					self.sockx.close()
					return False
			for paths in path:
				if paths == self.path or paths == "*":
					obj = load["path"][least[len(least)-1]]
					if obj[paths] == "DENY":
						if self.authorised != [] and self.authorised[0] != "Authenticated":
							apt = create_header(location=self.path, status_code=["403", "default"], connection="close", httpver="HTTP/1.1")
							apt.set_server = "sipistoverdi"
							apt.set_compatible = "IE=edge"
							apt.accept_ch = "Viewport-Width, Width"
							apt.xss_protection = "0"
							apt.setit(object=b"403 Forbidden (file to be fixed, better design. To do).")
							self.sockx.send(apt.app)
							self.sockx.close()
							return False
					elif obj[paths] == "REDIRECT":
						apt = create_header(location="index.html", status_code=["301", "default"], connection="close", httpver="HTTP/1.1")
						apt.set_server = "sipistoverdi"
						apt.set_compatible = "IE=edge"
						apt.accept_ch = "Viewport-Width, Width"
						apt.xss_protection = "0"
						apt.setit(object=b"empty")
						self.sockx.send(apt.app)
						self.sockx.close()
						return False
	@CheckHost.setter
	def set_path(self, path:str) -> str:
		self.path = path
	@CheckHost.setter
	def set_sock(self, sock):
		self.sockx = sock