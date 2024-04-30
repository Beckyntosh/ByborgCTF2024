# Docler_CTF_2024

## Who am I? Part 1
Welcome to the future of streaming! Our team is thrilled to announce our latest venture: a cutting-edge streaming platform that's set to redefine the digital landscape. However, there's a twist! In the spirit of digital espionage and cyber sleuthing, we've decided to keep our project under wraps. Only the most astute and skilled hackers can uncover the secrets we've meticulously hidden within our development environment.
You can find the site here: http://padawan.itsec.lu:8080/

1. Visit http://padawan.itsec.lu:8080/
2. Right click and view page source code or highlight the website
   ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/c19d7f0d-68a0-4e4a-b072-ae2049d894e3)

3. The first flag is on the top of the website
4. You can also highlight the website to see the flag:
   ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/d2353b06-2dc9-4479-8009-74c271d22eee)


## Who am I? Part 3
Who am I? The Robots?
Can you fin the Robots on the new streaming site? 
http://padawan.itsec.lu:8080

1. Visit the given URL
2. The description mentioned robots. There is a txt file on websites called robots.txt that is used to manage crawler traffic
3. Upon visiting http://padawan.itsec.lu:8080/robots.txt you can find the flag
   
![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/6b025748-d77c-4e11-9591-6ad88afff2fc)


## Who am I? Part 4
Who am I?  A Fashion Designer?
Find my style to get the flag on the new streaming site.
http://padawan.itsec.lu:8080/

1. Visit the given URL
2. Right click to inspect the source code or use ctrl+shift+I to see the developer tools
3. In the source code, there is a comment line: <!-- <link rel="stylesheet" href="styles.css"> -->
4. In the developer tools, navigate to elements to see the source code
5. Visit the http://padawan.itsec.lu:8080/style.css
   
   ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/312871df-ea69-4047-a796-91ef27891476)


## Quality Software
There's this software developer company called Quality Software Engineering Oslo. I think they stole our product code, so I need their Github password. Can you find it?

1. First step is to google Quality Software Engineering Oslo
2. There is a place registered in Oslo on Google Maps:

   ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/09b57576-7d75-4610-8a62-e78184f76f9e)

4. Looking at the reviews, there is a picture of a whiteboard:

   ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/db31a1f9-561b-4fb1-83f5-7cf327208f3e)

5. And the flag can be found on the picture, they wrote their password on it: Anton9202


## Renting in Oslo
I am renting an apartment in Oslo with a company called Quality Living. They archived their website, but I remember they had a table where I could see the prices of all apartments. I want to move into my neighbor's apartment, which is about 33 square meters. Can you help me find the price?

1. Google the given company Quality Living and their website: https://www.qualityliving.no/home-en/
2. The prices are no longer available  on the site but there is soemething called the way back machine that stores snapshots of websites so you can see how a website looked like 1 year ago, 5 years ago or even in the 90s if the site is that old.
3. Visit web.archive.org and type in the found web site
   ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/a8c178f4-625e-42e2-b4bf-80866796de83)

4. Chose any date from 2023
5. https://web.archive.org/web/20230322003228/https://www.qualityliving.no/ql-ulven-no/
   ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/ffb9d164-efcf-4944-b42f-afa6124c857a)


## Vacation
I visited this picture perfect street with my best friend, but cannot seem to recall the name of it. Can you help me find it, so I can visit it again? I have a picture of it attached.

1. You can use reverse image search to find similar photos
2. Use https://images.google.com/ ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/04fd4d47-4f6d-4617-94f4-d12bd6e4c54b)

4. Click on the TripAdvisor search results: ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/c8de7da8-287e-4e9e-846c-90b4648e2a5c)

5. You can see that this is the oldest street in Oslo, Google this information to find the name of the street: ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/11870524-aefa-4b8b-aaa6-7ace0030840e)



## Secret Vault
Can you find beckyntosh’s secret vault? She loves building new projects but cannot keep it secret if she is proud of it.

1. We have a user name, Beckyntosh, you can start by googling it
2. The description mentioned building projects and the google results shows results on hackingarena.com which a CTF site and also on GitHub where you can share your code project.
3. You can search Beckyntosh on GitHub: github.com/Beckyntosh and see a secret-vault in the repositories
4. Going through the project, in the www folder there is an index.php with hard coded secret key:
```
# Simulated database of vault access keys
VAULT_KEYS = {
    "admin": "5f4dcc3b5aa765d61d8327deb882cf99",  
}
```

## Venti Pumpkin Spice Latte
I got a free Venti Pumpkin Spice Latte for checking subdomains. I found one interesting but the responsible person only speaks French. Which subdomain have I discovered?

1. The name refers to Starbucks, hit can also be discovered by googling the name of the challenge: ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/2a71e895-af93-4b38-9213-0c3059c77b2d)

2. The name refers to Starbucks and the French part is to find a domain based in a French speaking country like France, Canada etc...
3. You can use dnsdumbster to find subdomains and the country they located in: ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/62b15dc8-c2e0-44b8-a9cd-afddb7a2240f)



## Secret Message
We have captured a message from the hacker group targeting our company but it seems like just music lyrics, or is there something in it?


Is this. the real life?. Is this just fantasy?.
Caught in a landslide, no escape from reality.
Open yo-ur eyes., look up to the skies and s-ee.
I'm. just a p-oor boy, I need no sympathy.
Because I'm easy come, easy go, little high, little low.
Any way the wind blows doesn't really matter to me, to-me
Mama-., just k-illed a man
Put a gun against his head, pulled my trigger, now he's dead.
Mama, life had just begu-n, but now. I've go-ne and thrown it all awa-y
Mama, ooh. didn't mean to make you cry.
If I'm n-ot back again this time tomorrow, Carry -on, carry -on as if nothing really matters
Too late. my time has come. Sends shivers down my-spine, body's aching all the time
Goodbye-everybody, I've got to go, Gotta leave you all behind and face the truth.
Mama, ooh (any-way the wind blows). I don't wanna die. I sometimes wish I'd never been born at all

1. If you look at the text, it is a lyrics
2. Looking at the original lyrics, there odd dots and dashes
3. If you seperate this from the text you get this: ... . -.-. .-. . - -.- . -.-- ..-. --- ..- -. -..
4. It is a morse code that can be reversed to plain text: SECRETKEYFOUN
5. For reversing it, you can use cyberchef: https://gchq.github.io/CyberChef/#recipe=To_Morse_Code('-/.','Space','Line%20feed')&input=U0VDUkVUS0VZRk9VTkQ

   
## Hash 1
A rookie developer accidentally committed an MD5 hash of a critical password to a public repository. Your task is to crack this hash to retrieve the password. The password is a common dictionary word.

Hash: 482c811da5d5b4bc6d497ffa98491e38

1. You can google the hash value and fin the plain text version of it among the results
2. You can also use any MD5 decryptor site like: https://md5.gromweb.com/?md5=482c811da5d5b4bc6d497ffa98491e38

## AirHash
A group of hackers has threatened the aviation industry by targeting  specific aircraft, encrypting their tail numbers in the airline's database. One particular aircraft has been compromised, and its encrypted tail number needs to be decrypted urgently to ensure its safety. The tail number follows the standard American registration pattern, where it starts with an 'N', followed by up to 5 digits, and can optionally end with up to two letters. The encryption used is SHA-256. Your mission is to use Hashcat with a mask attack to decrypt the tail number and ensure the aircraft's security.

Hash: 57aa9daa889647c97078b84f9616c5d723072cc32603f0422507f36de14eac92

1. We know that the tail number follows the standard American registration pattern, where it starts with an 'N', followed by up to 5 digits, and can optionally end with up to two letters e.g., N123AB 
2. We can use a hash identifier to detect the type of the hash: https://hashes.com/en/tools/hash_identifier which SHA-256
3. Hashcat has a masking function:
 ```
   hashcat -a 3 -m 1400 <provided_hash> -1 ?u?d -2 ?d?l?u N?2?2?2?2?2?1?1
```

## Be My Valentine
I shared my special moment on Instagram and I want to keep the location secret for the mystery. Can you play detective and uncover where I celebrated this day of love?

1. Download the picture
2. Reverse image search will not help now, but you can right click on the image and navigate to properties: ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/9ae09489-6fa3-4600-839f-7f2eeff75f5f)
3. In the properties window, navigate to the details where you can see the GPS coordinates: ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/9b51512b-8ebc-4b1a-beb6-409a6efa55cb)
4. ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/5b317fe5-7a69-47fc-8ce6-01f2f95a9cec)


## Be My Valentine - Phone
Have you seen my Valentine's day picture? Can you tell what kind of phone I own?

1. Download the picture
2. Reverse image search will not help now, but you can right click on the image and navigate to properties: ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/9ae09489-6fa3-4600-839f-7f2eeff75f5f)
3. In the properties window, navigate to the details where you can see the type pf the phone: ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/fc36f67a-25cf-4708-b35a-5a67ba78039f)


## IT Audit 
We are having an ISO 27001 Audit, Can you help us make sure we pass? We are worried about A.11 - Physical and Environmental Security, and specifically, the control A.11.2.9 which is the "Clear Desk and Clear Screen Policy." We heard gossip about the IT Security team in the Luxembourg office and in the Budapest office that they are not preparing for the audit. They are provided the audit evidence, see it attached.

1. Download the attached picture
2. If you take a careful look at the picture, there is a sticky notes in the background with the password: ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/d54bee44-9e3c-4d0d-9add-d52359980810)



## IT Audit 2
The audit evidence has been sent to the auditors, but the IT Security team did not use the secure file share, but a password protected zip. Are they using Bitwarden to store passwords or maybe sticky notes with the password?

1. If you got the password from the IT Audit 1 challenge, you can use the password to unzip the file
2. The zip file containing a flag.txt file


## Super Bowl
The IT Security team is going on a team building event and they are going to watch the Super Bowl together. They were informed that the Wi-Fi password hasn't changed since 2014. Can you find the password before the IT Security does?

1. We have the following information: Super Bowl, 2014 and password
2. Google these three words, use " so the search result must contain an exact match to the provided words:![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/8d738bd2-2b4c-4371-b80c-a7f087b0b423)

3. We can see several articles about the Super Bowl password being broadcasted:![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/cad56835-9a3e-4f00-b489-b489b1bf322e)

4. You can read the password from the above picture


## Boarding
Attention, all passengers. This is the final boarding call for Luxair flight ??? number with non-stop service from Budapest to Luxembourg. We kindly ask the Byborg IT Security team’s passengers to proceed to Gate 14 immediately for boarding!

1. We need to find the flight of a non-stop Budapest (BUD) and Luxembourg (LUX) flight.
2. There are several sites where you can look for it e.g.: skyscanner, Luxair, Momondo or the airport sites.
3. Visiting the Luxembourg Airport website we can see that the direct flights from Budapest are operated by Luxair: ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/832236f0-8b75-4dab-913b-e7e53209e22b)

4. You can also directly search on the Luxair website: ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/9ee7acf1-ca4f-4bed-a1dd-7849634fdb00)

5. You can see the flight number on both sites: Luxair (LG5808)


## Meeting
We have a colleague in the IT Security team named Akos Timko, working in the Budapest Office, where Rebeka Toth used to work before becoming a contractor from abroad. But have they met before Docler? Find the place where Rebeka and Akos met for the first time

1. Look at LinkedIn of Akos and Rebeka to find their work history
2. Both Akos and Rebeka have worked at KPMG Advisory Hungary from 2020 to 2022


## Simulation
Can you find the secret in the loop? Unzip the file and escape the simulation to retrieve your flag!

1. The provided file is a password protected zip file 
2. We can peek into the file and see there is another zip with 5 numbers in the name (7407): ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/35d7d612-b0f5-4769-b9ec-c916fd68ea43)

3. Try to use the 7407 as password, and it works
4. Doing this again we can see that the passwords always the name of the previous file
5. We have no idea how many zip files are nested into each other, but we can write an easy python script to unzip all the files, but we can create a python script for example like this:
 ```
import sys
import zipfile
import optparse
from threading import Thread

# Unzipper Function
def extractFile(zname):
    try:
        zFile = zipfile.ZipFile(zname) 
        file_info =  zFile.infolist()
        filename =  file_info[0].filename
        password = filename.split(".")
        zFile.extractall(pwd = password[0])
        print "The file " + zname + " successfully extracted with password " + password[0]
        last_file = filename
        extractFile(filename)
        
        
       
    except:
        print "Did the script fail or is it over ?" # Incase the script fails due to wrong 
        print "The Last file I unzipped was " + zname
    
        
def main():
    parser = optparse.OptionParser('usage: zipcracker.py ' + '-f <zipfile>')
    parser.add_option('-f', dest='zname',type='string',help='specify zip file')
    (options,args) = parser.parse_args()
    if (options.zname == None):
        print parser.usage
        exit(0)
    else:
        zname = options.zname
    extractFile(zname)

if __name__ == '__main__':
    main()
 ```

## Phishing 1
I got this email saying I have to pay my Netflix, I see the amount deducted from my Revolut. Can you find me the address where I can reply?

1. Download the attached email and open it in a txt reader
2. We can see that it says it is from info@netflix.io: ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/10c60931-9f72-43e5-ac2f-94844a7d2daf)

3. However it is possible to mask the sender and make it look like as if it was send on behalf of someone else. However, it is possible to see the real email address by hitting reply to if the email is in your inbox or by checking the return path: ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/5427d3a8-31b6-46dc-9ccd-c8e31db938b6)

4. Here we can see the real sender

## Where is the office dog?
Can you help us find Snuffles the office dog? 
The office dog was abducted by a group hackers in revenge of locking them out of our systems, we have captured a picture from them may contains the location of Snuffles, they are calling him Snowball now. Help us find him.

1. Downloaded the provided txt file
2. When you open it is just a Norwegian Christmas song
3. However if you look at the txt file, there are a lot of space at the end of each line
4. Searching for encryption or data hiding in spaces we can find that there is one that uses this method, called SNOW
5. You can install stegsnow on Kali Linux to decrypt the message: https://www.kali.org/tools/stegsnow/: ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/34ef0413-f0ad-429b-a4d9-b602f04469ba)


## Investigation
IT Security has captured an outgoing email with an image and zip file that may contain classified company information. Help us investigate the case.
Provided evidence number FE0260CE for the case
1. Trying to open the image, it looks as if it broken, and zip file has a password that cannot be cracked with the usual wordlist files:

   ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/c7b684ef-c5c5-4ee0-9f2c-b0d9b4f82493)

2. We can assume that picture will contain the password for the zip, so we need to recover it somehow
3. Looking at the hex values we can notice something strange in the height and width 
4. We can see that it is indeed a PNG file but with zero height and width:

   ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/8e1bf196-bdbf-4193-94bd-bcc4ad3051fb)

5. Looking into PNG specification we can see that: "A PNG file is composed of an 8-byte signature header, followed by any number of chunks that contain control data / metadata / image data. Each chunk contains three standard fields – 4-byte length, 4-byte type code, 4-byte CRC – and various internal fields that depend on the chunk type."
6. We need to calculate the original height and width of the picture in order to restore it, which we can do by brute forcing combinations of different widths and heights to get same check sum. The original checksum of the PNG is the evidence number.
7. We can write a simple python code for the bruteforcing

```
    from zlib import crc32

crc = '0x52931e1d'

data = open("Evidence_Number_FE0260CE.png",'rb').read()
index = 12

ihdr = bytearray(data[index:index+17])
width_index = 7
height_index = 11

for x in range(1,2000):
	height = bytearray(x.to_bytes(2,'big'))
	for y in range(1,2000):
		width = bytearray(y.to_bytes(2,'big'))
		for i in range(len(height)):
			ihdr[height_index - i] = height[-i -1]
		for i in range(len(width)):
			ihdr[width_index - i] = width[-i -1]
		if hex(crc32(ihdr)) == crc:
			print("width: {} hegiht: {}".format(width.hex(),height.hex()))
	for i in range(len(width)):
		ihdr[width_index -i] = bytearray(b'\x00')[0]
  ```
8. The restored picture:

    ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/8af9b0db-ee04-49d6-bc11-9d003c43b011)

9. We can use the password from the picture to unzip the secret.7zp


## Leaked Teams Chat
The Teams chat of our rival company has been leaked, can you help us decrypt and understand their conversation?

Nyrk: Qb lbh xabj jul Fgnpl qvqa'g nccyl sbe gur znantre cbfvgvba?
Pnfrl: V guvax fur srryf gung fur'q or zber hapregnva va n uvture ebyr.
Nyrk: Gung znxrf frafr. Qvq fur fnl jung fur'f cynaavat gb qb gura?
Pnfrl: Lrf, fur'f tbvat gb pbzznaq gur tnzr avtugf ng gur puneyvr qnl pner.
Nyrk: Ol gur jnl, V'ir svavfurq gur synt sbe gur pynffvp png. Gur synt vf: PGS{Fu1sg3q_Qe3nZf_Ne3_GuR_O3fG}

1. At first the chat seems only gibberish, but it is actually encrypted
2. You can use for example CyberChef to decrypt it: https://gchq.github.io/CyberChef/
3. The encryption is ROT13: ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/d2ffe961-fcb9-4bcf-98f3-4f9a2c12341f)



## Scan me
Scan to the QR code to get the flag.

1. Download the attached QR code
2. You can scan it with your phone to see the flag in it: ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/37baa96a-32fe-43c8-af85-9f44581b4ef2)


## Hash 2
We discovered a leaked database that contains the hashes of or company passwords. Can you check if any of them are cracked? The answer is the plain text version of the cracked hash

256ed3ca686cdb7f74a172af401f1faa
dd6ccf0a0a427edb8647f5f477d052da
c6035a3679321cf868bbf0b4a7690524

1. You can copy the hash and paste into too Google to find the plain text value: ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/e711687f-2bd3-4da5-94c1-33e6ca576a2c)

2. Or you can use a hash type identifier to find the type of the hash which is MD5 like https://hashes.com/en/tools/hash_identifier:![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/317bee39-f981-4ec4-80fa-3f0e4d8afa16)

3. After that, search for an MD5 decrypter site like https://md5decrypt.net/en/: ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/63832265-88bf-4f70-ad08-8b6869bc3208)


## Hash 3 Tock it!
Decrypt the SHA-256 hash to Rock my new secret password.

73a04957d8d106571943ab8b144db362ea70243a4b0e5c6b30adbcbfb9f59173

1. Googling and online hash decrypter tools does not give any results, however the the title and description uses the word rock. There is a common password list called rock you: https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
2. You can use hashcat on Kali to crack the provided hash: ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/28061c3b-d8c0-433e-a6cf-ec3141f4b49d)

3.  In a couple of minutes you will have the result: ![image](https://github.com/Beckyntosh/Docler_CTF_2024/assets/76634373/91a35c35-b298-4614-a94d-6acce7e94b62)





