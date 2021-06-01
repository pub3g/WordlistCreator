# WordlistCreator

Step1: Save this python script as burplist.py

```
import xml.etree.ElementTree as ET
import urllib
import base64
import math
import sys
import re

# usage: Open Burp, navigate to proxy history, ctrl-a to select all records, right click and "Save Items" as an .xml file. 
# python burplist.py burprequests.xml
# output is saved to wordlist.txt

def entropy(string):
        #"Calculates the Shannon entropy of a string"
        # get probability of chars in string
        prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]

        # calculate the entropy
        entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])

        return entropy

def avgEntropyByChar(en,length):
	# calulate "average" entropy level
	return en / length 


tree = ET.parse(sys.argv[1])
root = tree.getroot()
wordlist = []

for i in root:

	# preserve subdomains, file/dir names with . - _
	wordlist += re.split('\/|\?|&|=',i[1].text)

	# get subdomain names and break up file names
	wordlist += re.split('\/|\?|&|=|_|-|\.|\+',i[1].text)

	# get words from cookies, headers, POST body requests
	wordlist += re.split('\/|\?|&|=|_|-|\.|\+|\:| |\n|\r|"|\'|<|>|{|}|\[|\]|`|~|\!|@|#|\$|;|,|\(|\)|\*|\|', urllib.unquote(base64.b64decode(i[8].text)))

	# response
	if i[12].text is not None:
		wordlist += re.split('\/|\?|&|=|_|-|\.|\+|\:| |\n|\r|\t|"|\'|<|>|{|}|\[|\]|`|~|\!|@|#|\$|;|,|\(|\)|\*|\^|\\\\|\|', urllib.unquote(base64.b64decode(i[12].text)))

auxiliaryList = list(set(wordlist))
final = []
avgEntropyByLength = {}

for word in auxiliaryList:
	if word.isalnum() or '-' in word or '.' in word or '_' in word:
		en = entropy(word)
		# remove "random strings" that are high entropy
		if en < 4.4:
			final.append(word)

final.sort()

with open('wordlist.txt', 'w') as f:
    for item in final:
        f.write("%s\n" % item)


print "wordlist saved to wordlist.txt"
```

Stpe 2: Save in scope burp files as target.xml ( proxy-> burp history -> ctrl+a -> save file as target.xml ), before doing this set scope as as per your target and browse the website as normal user so that burp history capture everything which in scope.

Step 3: Now use this command : ` python burplist.py target.xml ` wordlist.txt will be created

Step 4: Clean the wordlist.txt by using another script 

```
#! /bin/bash
# To view the changes do:
# diff original.txt_cleaned <(sort original.txt) | more

regexes=(
    "[\!(,%]" # Ignore noisy characters
    ".{100,}" # Ignore lines with more than 100 characters (overly specific)
    "[0-9]{4,}" # Ignore lines with 4 or more consecutive digits (likely an id)
    "[0-9]{3,}$" # Ignore lines where the last 3 or more characters are digits (likely an id)
    "[a-z0-9]{32}" # Likely MD5 hash or similar
    "[0-9]+[A-Z0-9]{5,}" # Number followed by 5 or more numbers and uppercase letters (almost all noise)
    "\/.*\/.*\/.*\/.*\/.*\/.*\/" # Ignore lines more than 6 directories deep (overly specific)
    "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}" # Ignore UUIDs
    "[0-9]+[a-zA-Z]+[0-9]+[a-zA-Z]+[0-9]+" # Ignore multiple numbers and letters mixed together (likley noise)
    "\.(png|jpg|jpeg|gif|svg|bmp|ttf|avif|wav|mp4|aac|ajax|css|all)$" # Ignore low value filetypes
    "^$" # Ignores blank lines
)

wordlist=$1
echo "[+] Cleaning ${wordlist}"
original_size=$(cat ${wordlist} | wc -l)

# Build command
cmd="cat ${wordlist}"
for regex in "${regexes[@]}"; do
    cmd="${cmd} | grep -vE '${regex}'"
done

# Add sort, uniq, and save to new file
cmd="${cmd} | sort | uniq > ${wordlist}_cleaned"

# Execute command
eval $cmd

# Calculate changes
new_size=$(cat ${wordlist}_cleaned | wc -l)
removed=$((original_size-new_size))

echo "[-] Removed ${removed} lines"
echo "[+] Wordlist is now ${new_size} lines"
echo "[+] Done"

```

Save above script as wordlist_cleaner.sh & run a command chmod +x wordlist_cleaner.sh

Step 5: run another command ` ./wordlist_cleaner.sh wordlist.txt
