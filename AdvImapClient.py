from concurrent.futures.process import _chain_from_iterable_of_lists
from email import policy
from email.message import Message
from email.mime import base
from io import BytesIO
import re
import imaplib
import email
from pyexpat.errors import messages
from time import sleep
from tabulate import tabulate
import os
import json
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
import datetime
from datetime import date
from dateutil.relativedelta import relativedelta
from plyer.utils import platform
from plyer import notification
import threading
import email.header
import quopri
import re
import base64
import signal
import sys
from cryptography.fernet import Fernet
import hashlib
import webbrowser

class bcolors:
    ''' Used for coloring text in the terminal '''
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def decoder(input, encoding = "") -> str:
    '''
    Decodes the given input in bytes from both quoted-printable and base64 and returns a decoded string.
    For converting elements to bytes there are mainly to ways:
    - When working with message.get("From") you have to use str.encode(---) 
    - When in "for part in message.walk()", part type is message and its converted by doing part.as_bytes()
    '''
    outputFile = BytesIO()
    try:            #tries to convert from base64, if it fails 
        if encoding == "quoted-printable":
            inputFile = BytesIO(input)
            quopri.decode(inputFile, outputFile)
        elif encoding == "base64":
            input = base64.decodebytes(input)
            outputFile = BytesIO(input) 
        else:
            outputFile = BytesIO(input)

        decoded = outputFile.getvalue().decode('utf-8')
    except: 
        decoded = outputFile.getvalue().decode("iso-8859-1")    # for latin characters
    
    return decoded

def formatDate(oldFormat) -> str:
    ''' Convert from 01-01-2000 to 01-Jan-2000 '''
    months_literal = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]
    parts = oldFormat.split("-")    
    return parts[2] + "-" + months_literal[int(parts[1]) - 1] + "-" + parts[0]


def intersection(lst1, lst2) -> list:
    ''' Intersection of two lists '''
    if len(lst1) > 0 and len(lst2) > 0:
        lst4 = lst1[0].decode().split()
        lst5 = lst2[0].decode().split()
        lst3 = [value for value in lst4 if value in lst5]
        return lst3
    else:
        return []

def notificationDeamon():
    ''' Thread dedicated to mailbox notifications '''
    while(not finished):
        for item in source_json["folders"]:
            if item["alias"].lower() != "sent":
                ids = []
                ids1 = []
                ids2 = []
                imap2.select(item["realName"])
                typ, ids1 = imap2.uid('search', "UNSEEN")
                criteria = "("   
                if permit_sub == "" and permit_mailb == "":                
                    for element in deny_mailb.split("-"):
                        if element != "":
                            criteria = criteria + "NOT FROM" + ' \"' +  element + '\" '  
                    for element in deny_sub.split("-"):
                        if element != "":
                            criteria = criteria + "NOT SUBJECT" + ' \"' +  element + '\" '
                elif deny_sub == "" and deny_mailb == "":                
                    for element in permit_mailb.split("-"):
                        if element != "":
                            criteria = criteria + "FROM" + ' \"' +  element + '\" '
                    for element in permit_sub.split("-"):
                        if element != "":
                            criteria = criteria + "SUBJECT" + ' \"' +  element + '\" '
                criteria = criteria.strip() + ")"
                if len(criteria) > 2:           # the parenthesis contains parameters
                    typ, ids2 = imap2.uid('search', criteria)   
                    ids = intersection(ids1, ids2)                    
                else:
                    ids = ids1[0].decode().split()
                if len(ids) > 0:
                    for id in ids:            
                        typ, messageRaw = imap2.uid('fetch',id,'(RFC822)')
                        message = email.message_from_bytes(messageRaw[0][1], policy=policy.default)
                        notification.notify(
                        title=re.sub(r'<.+?>', '', str(message.get("From"))),
                        message=decoder(str.encode(message.get("Subject"))),
                        app_name="AdvIMAPClient",
                        app_icon='icon.' + ('ico' if platform == 'win' else 'png')
                        )
        sleep(POLLING_SEC)           
       

def getUpdatedJSON() -> str:
    ''' Opens the json file and returns it as a string'''
    source = ''
    with open ("./source.json") as s:
        source = s.read()
    s.close()
    return json.loads(source)    # converting string in json object


''' Parameters and variables '''
CURR_FOLD = "INBOX"       # default folder
PATH = "Advanced IMAP client\\" + CURR_FOLD      # prompt line
IMAP_URL = 'imap.gmail.com'     # imap server url
POLLING_SEC = 20         # polling interval in seconds
source_json = ""

''' Login '''
found = False
success = False

while(True):
    imap = imaplib.IMAP4_SSL(IMAP_URL)
    imap2 = imaplib.IMAP4_SSL(IMAP_URL)
    while(True):
        source_json = getUpdatedJSON()
        success = False
        accPassword = user = password = ""
        print(f"Insert your {bcolors.BOLD}access password{bcolors.ENDC} (or 'signup' if you haven't it yet): ", end="")
        accPassword = input().strip()

        if accPassword != "signup": 
            while not success:
                source_json = getUpdatedJSON()
                if len(source_json["access"]) > 0:
                    for i in range(0, 32-len(accPassword)):
                        accPassword = accPassword + "="         # padding for encryption key (must be 32 chars)
                    hasher = hashlib.sha256()
                    hasher.update(str.encode(accPassword))
                    dig = str(hasher.digest())
                    for item in source_json["access"]:
                        if item["accPassword"] == dig:      # checking access password
                            f = Fernet(base64.b64encode(str.encode(accPassword)))

                            success = True
                            user = f.decrypt(str.encode(item["user"][2:-1])).decode("utf-8") 
                            password = f.decrypt(str.encode(item["password"][2:-1])).decode("utf-8")
                            break

                print(f"\n{bcolors.HEADER}Veryfing credentials...{bcolors.ENDC}")            
                try:
                    # verify that the credentials are valid
                    imap.login(user,password)
                    imap2.login(user,password)    # used for notifications through polling

                except:
                    print(f"\n{bcolors.HEADER}Access not accomplished, check inserted values or press 'exit' for re-starting the program: {bcolors.ENDC}",end="")
                    accPassword = input().strip()
                    if accPassword == "exit":
                        break
                    continue

                if success:
                    break
                else:
                    continue   
            break 
        else:
            # here the user has to insert mailbox credentials in order to use the access password in later accesses
            while not success:
                source_json = getUpdatedJSON()
                print(f"\nInsert your {bcolors.BOLD}mailbox{bcolors.ENDC}: ", end="")
                user = input().strip()
                print(f"Insert your {bcolors.BOLD}password{bcolors.ENDC}: ", end="")
                password = input().strip()
                
                print(f"\n{bcolors.HEADER}Veryfing credentials...{bcolors.ENDC}")
                try:
                    # verify that the credentials are valid
                    imap.login(user,password)
                    imap2.login(user,password)    # used for notifications
                    
                except:
                    if user == "exit":
                        break
                    print(f"\n{bcolors.HEADER}Access not accomplished, retry inserting the access password or type 'exit' as mailbox for re-starting the program: {bcolors.ENDC}")
                    continue

                success = True
            
            
            # open json file for checking whether the password is already used and for writing new data
            tmp = getUpdatedJSON()

            available = False
            dig2 = ""
            while not available: 
                available = True       
                print(f"Insert your {bcolors.BOLD}access password{bcolors.ENDC}: ", end="")
                accPassword = input().strip()
                if len(accPassword) > 32 or len(accPassword) < 8:          # by setting the min length we avoid having a password equal to "signup"
                    print("Password lenght must be between 8 and 32 characters")
                    available = False
                    continue

                for i in range(0, 32-len(accPassword)):
                    accPassword = accPassword + "="             # padding for reaching 32 characters so it can be used for generating Fernet key
                hasher2 = hashlib.sha256()
                hasher2.update(str.encode(accPassword))
                dig2 = str(hasher2.digest())
                for element in tmp["access"]:
                    if element["accPassword"] == dig2:      # "accPassword"
                        available = False
            
            f = Fernet(base64.b64encode(str.encode(accPassword)))
            userEncr = f.encrypt(str.encode(user))
            passwordEncr = f.encrypt(str.encode(password))

            # json object to be inserted into main json file
            toWrite = {
                "user":str(userEncr),
                "password":str(passwordEncr),
                "accPassword":dig2      # str(hasher3.digest())
            }

            toAppend = tmp["access"]
            toAppend.append(toWrite)
            
            with open ("./source.json","w") as s2:
                json.dump(tmp,s2)   
            s2.close()
            break
            
    if not success:         # if the access is not accomplished, the login step must be executed again
        continue


    print(f"{bcolors.HEADER}Access accomplished with success\n{bcolors.ENDC}")

    imap.select(CURR_FOLD)      # selecting the folder to work in

    command = ""
    finished = False

    # permit and deny lists for notifications
    permit_sub = ""     
    permit_mailb = ""
    deny_sub = ""
    deny_mailb = ""

    notificationT = threading.Thread(target=notificationDeamon)       # starting notification deamon thread
    notificationT.start()

    ''' Program execution ''' 

    while command != "exit" and command != "logout":
        arguments = command.split(" ")     # divide command string into arguments
        
        if arguments[0] == "man":
            ''' Display man page, if a command is specified then its detailed information is displayed '''
            try:
                for item in source_json["manual"]:
                    if arguments[1].lower() == item["commandName"].lower(): 
                        print(item["description"])
                
            except:
                print(f"{bcolors.OKBLUE}\n------ Advanced IMAP Client user manual ------\n{bcolors.ENDC}")
                print("List of possibile commands:")
                print(f"  {bcolors.BOLD}cd{bcolors.ENDC} -> change folder mailbox")
                print(f"  {bcolors.BOLD}clear{bcolors.ENDC} -> clean the terminal")
                print(f"  {bcolors.BOLD}view{bcolors.ENDC} -> open a specified mail")
                print(f"  {bcolors.BOLD}show{bcolors.ENDC} -> display list of mail, depending on the folder")
                print(f"  {bcolors.BOLD}files{bcolors.ENDC} -> open the folder containing attachments")
                print(f"  {bcolors.BOLD}exit{bcolors.ENDC} -> quit from mail client")
                print(f"  {bcolors.BOLD}delete{bcolors.ENDC} -> delete a specific mail")
                print(f"  {bcolors.BOLD}stats{bcolors.ENDC} -> plot some stats of the mailbox")
                print(f"  {bcolors.BOLD}search{bcolors.ENDC} -> search mails containing words")
                print(f"  {bcolors.BOLD}logout{bcolors.ENDC} -> logout from the current mailbox")
                print(f"  {bcolors.BOLD}permit{bcolors.ENDC} -> permits notifications of only certain mailboxes or mail objects")
                print(f"  {bcolors.BOLD}deny{bcolors.ENDC} -> deny notifications of only certain mailboxes or mail objects")
                print(f"  {bcolors.BOLD}listpermit{bcolors.ENDC} -> list of the permitted mailboxes or mail objects")
                print(f"  {bcolors.BOLD}listdeny{bcolors.ENDC} -> list of the denied mailboxes or mail objects")
                print("\nFor more in depth informations, type man _commandName_\n")

        elif arguments[0] == "cd":
            ''' Change mailbox directory '''
            try:
                for item in source_json["folders"]:
                    if arguments[1].lower() == item["alias"].lower():
                        CURR_FOLD = item["realName"].replace("'",'"')       # necessary for sent directory
                    elif arguments[1] == "?":       # if second argument is "?", all possibile directories are displayed
                        print("Folder names: {inbox, starred, spam, important, bin, drafts, sent}")    
                        break                               
            except:
                print("Invalid input\n")
            
            imap.select(CURR_FOLD)
            PATH =  PATH[0:PATH.index("\\")] + "\\" + CURR_FOLD

        elif arguments[0] == "clear":
            ''' Typical function, clear the terminal '''
            os.system('cls' if os.name == 'nt' else 'clear')
        
        elif arguments[0] == "view":
            ''' Open a specific message '''
            try:
                uid = arguments[1]
                #uid.decode().split()
                typ, messageRaw = imap.uid('fetch',uid,'(RFC822)')        
                if messageRaw[0] == None:
                    print("Invalid UID, retry please or use 'show' command for displaying the available ones")
                else:
                    message = email.message_from_bytes(messageRaw[0][1], policy=policy.default)
                    print(f"\n{bcolors.OKCYAN}From{bcolors.ENDC}: ",message.get("From"))
                    print(f"{bcolors.OKCYAN}To{bcolors.ENDC}: ",message.get("To"))
                    print(f"{bcolors.OKCYAN}BCC{bcolors.ENDC}: ",message.get("BCC"))
                    print(f"{bcolors.OKCYAN}Date{bcolors.ENDC}: ",message.get("Date"))
                    print(f"{bcolors.OKCYAN}Subject{bcolors.ENDC}: ",decoder(str.encode(message.get("Subject"))))
                    print(f"{bcolors.OKCYAN}Body{bcolors.ENDC}: ")

                    
                    for part in message.walk():
                        encoding = ""
                        for element in part.items():
                            if element[0] == 'Content-Transfer-Encoding':
                                encoding = element[1]
                        
                        if part.get_content_type() == 'text/plain':
                            print(decoder(str.encode(part.get_payload()), encoding)) 
                        elif part.get_content_type() == 'text/html':
                            decodedText = decoder(str.encode(part.get_payload()), encoding)
                            '''
                            almost every message has content-type test/html even if it's not a complete html page so in that cases it can be showed in the terminal
                            otherwise, when it contains the doctype in the first line, that message needs to be shown in the browser
                            '''
                            if decodedText.find("<!DOCTYPE html>") != -1:     # if the decoded text contains a complete HTML page, that page is displayed in the browser
                                try:
                                    with open('tmp/webmail.html', 'w', encoding='utf-8') as f:
                                        f.write(decodedText)
                                    f.close()
                                    url = os.path.join('./tmp', "webmail.html")
                                    webbrowser.open(url, new=2)  # open in new tab
                                except FileNotFoundError:
                                    print("The 'tmp' directory does not exist")
                            
                            
                    print("\n")
                    for part in message.walk():
                        if part.get_content_maintype() == 'multipart':
                            continue
                        if part.get('Content-Disposition') is None:
                            continue

                        fileName = part.get_filename()
                        if bool(fileName):
                            filePath = os.path.join('./Attachments', fileName)
                            if not os.path.isfile(filePath):           # forse questo if si può togliere in modo da fare vedere il messaggio di download sempre, anche se è già stato visualizzato il messaggio (e quidni scaricato l'allegato)
                                fp = open(filePath, 'wb')
                                fp.write(part.get_payload(decode=True))
                                fp.close()
                                path = os.path.realpath("./Attachments")
                                os.startfile(path)
                                print('Downloaded "{file}" from email titled "{subject}"'.format(file=fileName, subject=decoder(str.encode(message.get("Subject")))))
                            else:      
                                print('Already downloaded "{file}" from email titled "{subject}"'.format(file=fileName, subject=decoder(str.encode(message.get("Subject")))))
                            
            except:
                print("arguments invalid in view")

        elif arguments[0] == "show":
            ''' Show list of mails '''
            data = []
            c = 0
            try:
                limit = 50     # default number of mails showed

                typ, ids = imap.uid('search',None,'ALL')
                ids = ids[0].decode().split()

                if len(arguments) == 2:
                    if re.findall("[0-9]+",arguments[1]) and int(arguments[1]) < len(ids):
                        limit = int(arguments[1])
                    elif arguments[1] == "bottom":
                        ids.reverse()                        
                elif len(arguments) == 3:        # avoiding exception
                    if arguments[2] == "bottom" or arguments[1] == "bottom":
                        ids.reverse()
                    if re.findall("[0-9]+",arguments[1]) and int(arguments[1]) < len(ids):
                        limit = int(arguments[1])
                    elif re.findall("[0-9]+",arguments[2]) and int(arguments[2]) < len(ids):
                        limit = int(arguments[2])

                if limit > len(ids):
                    limit = len(ids) - 1

                ids.reverse()

                isSent = True
                for item in source_json["folders"]:
                    if item["realName"] == CURR_FOLD and item["alias"] != "sent":
                        isSent = False


                for id in ids:
                    if c < limit:
                        typ, messageRaw = imap.uid('fetch',id,'(RFC822)')
                        message = email.message_from_bytes(messageRaw[0][1], policy=policy.default)
                        data.append([id, (re.sub(r'<.+?>', '', decoder(str.encode(message.get("To"))) if isSent else decoder(str.encode(message.get("From"))))) , decoder(str.encode(message.get("Subject"))), message.get("Date")])
                        c = c + 1
                    else:
                        break
                print("\n" + tabulate(data, headers=["UID","To" if isSent else "From","Subject","Date"]) + "\n")
            except:
                print("Something went wrong while fetching data")

        elif arguments[0] == "files":
            ''' Shows attachment folder '''
            path = os.path.realpath("./Attachments")
            os.startfile(path)
        
        elif arguments[0] == "stats":
            ''' Show some stats related to received mails '''
            workFolder = CURR_FOLD
            try:
                if arguments[1] == "spam":
                    print("Stats about spam percentage")
                    numNotSpam = 0
                    numSpam = 0
                    for item in source_json["folders"]:
                        if item["alias"].lower() == "spam":
                            imap.select(item["realName"])
                            typ, ids = imap.uid('search',None,'ALL')
                            numSpam = len(ids[0].decode().split())
                        elif item["alias"].lower() != "sent":
                            imap.select(item["realName"])
                            typ, ids = imap.uid('search',None,'ALL')
                            numNotSpam += len(ids[0].decode().split())

                    print("Spam emails number:", numSpam)
                    print("Not-spam emails number:",numNotSpam)

                    data = [numSpam, numNotSpam]
                    keys = ['Percentage of spam emails', 'Percentage of non-spam emails']
                    palette_color = sns.color_palette("rocket")
                    plt.pie(data, labels=keys, colors=palette_color, autopct='%.0f%%')
                    plt.show()

                elif arguments[1] == "plot":
                    now = datetime.datetime.now()        # current date 
                    
                    values = []
                    labels = []
                    dates = []
                    try:
                        if arguments[2] == "years":
                            if now.month == 1 and now.day == 1:
                                dates.append((now.date() + relativedelta(days=1)).isoformat())
                            else:
                                dates.append(now.date().isoformat())
                            startingYear = date(now.year,1, 1)
                            dates.append(startingYear.isoformat())
                            strLabel = str(formatDate(startingYear.isoformat()))
                            labels.append(strLabel.split("-")[2])
                            for i in range(1, 11):
                                dates.append((startingYear - relativedelta(years=i)).isoformat())
                                strLabel = str(formatDate((startingYear - relativedelta(years=i)).isoformat()))
                                labels.append(strLabel.split("-")[2])
                            plt.title("Number of emails received during last 10 years")

                        elif arguments[2] == "months":
                            if now.day == 1:
                                dates.append((now.date() + relativedelta(days=1)).isoformat())
                            else:
                                dates.append(now.date().isoformat())
                            startingMonth = date(now.year,now.month, 1)
                            dates.append(startingMonth.isoformat())
                            strLabel = str(formatDate(startingMonth.isoformat()))
                            labels.append(strLabel.split("-")[1])
                            for i in range(1, 12):
                                dates.append((startingMonth - relativedelta(months=i)).isoformat())
                                strLabel = str(formatDate((startingMonth - relativedelta(months=i)).isoformat()))
                                labels.append(strLabel.split("-")[1])   # va sistemato ordine
                            plt.title("Number of emails received during last 12 months")
                                
                        elif arguments[2] == "days":
                            dates.append((now.date() + relativedelta(days=1)).isoformat())
                            dates.append(now.date().isoformat())
                            strLabel = str(formatDate(now.date().isoformat()))
                            labels.append(strLabel.split("-")[0])
                            for i in range(1, 31):
                                dates.append((now.date() - relativedelta(days=i)).isoformat())
                                strLabel = str(formatDate((now.date() - relativedelta(days=i)).isoformat()))
                                labels.append(strLabel.split("-")[0])
                            plt.title("Number of emails received during last 30 days")
                        
                        else:
                            print("Invalid third argument of the command")
                            break

                        for j in range(0, len(dates)-1):
                            date_indexes = 0
                            for item in source_json["folders"]:
                                if item["alias"].lower() != "sent":
                                    imap.select(item["realName"])
                                    criteria = "(BEFORE " + '\"' + formatDate(dates[j]) + '\"' + " SINCE " + '\"' + formatDate(dates[j+1]) + '\"'")"
                                    #labels.append(dates[j] + " - " + dates[j+1])
                                    typ, ids = imap.uid('search', criteria)    #'(SINCE 01-Jan-2010)'
                                    ids = ids[0].decode().split()
                                    date_indexes = date_indexes + len(ids)
                            values.append(date_indexes)

                        print("Values:",values)
                        plt.grid(True,which="both")
                        plt.bar(labels, values)
                        plt.xticks(rotation=60)
                        plt.show()

                    except Exception as e:
                        print("something went wrong retry, ",e)

                imap.select(workFolder)           # after cycling through all folders, the one used before is selected again
            except:
                print("arguments not valid")

        elif arguments[0] == "search":
            ''' Fetching mails with search parameters '''
            try:
                criteria = "("
                for i in range(1, len(arguments)):
                    divider = arguments[i].index(":")
                    if (len(arguments[i][0:divider]) == 0 or len(arguments[i][divider + 1:]) == 0):
                        criteria = criteria + (arguments[i][0:divider].upper() + arguments[i][divider + 1:])
                    else:
                        criteria = criteria + (arguments[i][0:divider].upper() + ' \"' + arguments[i][divider + 1:]+'\"')
                    if i != len(arguments) -1:
                        criteria += ' '
                criteria = criteria+")"
                data = []
                c = 0
                typ, ids = imap.uid('search', criteria, "ALL")    # syntax: ('FROM "Google"')
                ids = ids[0].decode().split()
                ids.reverse()
                for id in ids:
                    if c < 50:
                        typ, messageRaw = imap.uid('fetch',id,'(RFC822)')   
                        message = email.message_from_bytes(messageRaw[0][1], policy=policy.default)

                        data.append([id, (re.sub(r'<.+?>', '', decoder(str.encode(message.get("From"))))) , decoder(str.encode(message.get("Subject"))), message.get("Date")])

                        c = c + 1
                    else:
                        break
                
                print("\n" + tabulate(data, headers=["UID","From","Subject","Date"]) + "\n")
            except:
                print("Something went wrong, retry or check search manual with 'man search'")
            
        elif arguments[0] == "delete": 
            ''' Delete a mail '''
            try:
                uid = arguments[1]
                for i in range(1, len(arguments)):
                    imap.uid('STORE', arguments[i], '+X-GM-LABELS', '\\Trash')

                print("Mail eliminated")
            except:
                print("Arguments invalid in delete")

        elif arguments[0] == "permit":
            ''' Permit notification from mailbox or subject containing certain characters '''
            deny_sub = ""
            deny_mailb = ""
            try:
                if len(arguments) == 3:
                    if arguments[1] == "subject":
                        permit_sub = permit_sub + "-" + arguments[2]
                    elif arguments[1] == "mailbox":
                        permit_mailb = permit_mailb + "-" + arguments[2]
                    elif arguments[1] == "all":
                        deny_sub = ""
                        deny_mailb = ""
            except:
                print("Invalid arguments in notification permission command")

        elif arguments[0] == "deny":
            ''' Deny notification from mailbox or subject containing certain characters '''
            permit_sub = ""
            permit_mailb = ""
            try:
                if len(arguments) == 3:
                    if arguments[1] == "subject":
                        deny_sub = deny_sub + "-" + arguments[2]
                    elif arguments[1] == "mailbox":
                        deny_mailb = deny_mailb + "-" + arguments[2]
                    elif arguments[1] == "all":
                        deny_sub = ""
                        deny_mailb = ""
            except:
                print("Invalid arguments in notification deny command")

        elif arguments[0] == 'listpermit':
            ''' Lists all parameters for permitted notifications '''
            print("Permit mailboxes list:", permit_mailb)
            print("Permit subjects list:", permit_sub)
        
        elif arguments[0] == 'listdeny':
            # TODO: sistemazione stringhe, pulizia
            ''' Lists all parameters for denied notifications '''
            print("Deny mailboxes list:", deny_mailb)
            print("Deny subjects list:", deny_sub)
            

        print(PATH+"> ", end="")   
        command = input().strip()   # removes external spaces form user's command


    finished = True
    imap.close()
    imap2.close()
    imap.logout()
    imap2.logout()
    if command == "exit":
        print("Quitting, may take few seconds...")    
        notificationT.join()    
        break
    elif command == "logout":
        print("Logging out, may take few seconds...")
        notificationT.join()            # duplicated code in order to show the print string before program sleeping    
        continue
    
