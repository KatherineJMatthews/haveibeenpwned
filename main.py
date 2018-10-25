import requests
import hashlib
from hashlib import sha1
from requests import RequestException


class Pwned:
    def __init__(self, agent):
        self.agent = agent
        self.header = {'User-Agent' : self.agent}

    def searchPassword(self, password): 
        #api url - grabs all passwords in database that begin with the 1st 5 digits it is sent   
        url = 'https://api.pwnedpasswords.com/range/'

        #Converts password into SHA-1 password hash
        hash_object = hashlib.sha1(bytes(password, encoding='utf-8'))
        hexdig = hash_object.hexdigest()
        hexdig = hexdig.upper()
        
        #first 5 characters of hash (for range of api)
        hsh = hexdig[:5]
        # variable for password safe/pwned
        msg = "-> safe"
        #api requests using requests
        resp = requests.get(url + hsh, headers=self.header)

        if resp.status_code == 200:
            data = resp.text
            data = data.splitlines()
            for item in data:
                #looks at the 35 digits of the result and compares it to the last 35 of the password hash
                if item[0:35] == hexdig[5:]:
                    #password is present in the repository (pwned)
                    msg = "-> pwned"
            return password + msg
        else:
            return password + " -> safe"

#grab list from input text file and read it into list variable            
list_ = open("input.txt").read().split()

#iterate over all items in list and run the search password function on each item
for item in list_:
    foo = Pwned('Pwned_App')
    data = foo.searchPassword(item)  
    print(data)

