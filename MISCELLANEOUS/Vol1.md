# Miscellaneous 1

## ipcalc

- To get a quick overview of a subnet:

```
ipcalc 192.168.1.0/24
```

This will display the network range, broadcast address, netmask, and other useful information.

- If you want to determine the IP range and other details for a specific IP and netmask:

```
ipcalc 192.168.1.25 255.255.255.0
```

This shows you what network the IP belongs to and the possible IPs in that subnet.

- If you need to break down a large network into smaller subnets, you can use:

```
ipcalc 192.168.1.0/24 -s 26
```

This will split the /24 network into /26 subnets and show you the ranges.

- If you just need the network and broadcast addresses, ipcalc can quickly provide them:

```
ipcalc 192.168.1.50/24 -b
```

- When dealing with multiple networks, you might want to check if they overlap. This is useful if you suspect there’s an overlap between subnets that could be exploited:

```
ipcalc 192.168.1.0/24 192.168.1.128/25
```

This compares the two ranges and tells you if they overlap.

- Sometimes, you might need to convert IPs between decimal, hexadecimal, and binary formats:

```
ipcalc --nocolor --dec --hex --bin 192.168.1.1
```

This will show you the IP in all these formats, which can be useful for certain types of analysis or when crafting custom packets.

- If you're given an IP range in a shorthand format (like CIDR), and you want to expand it into a full list of IPs, ipcalc can do that:

```
ipcalc --nocolor 192.168.1.0/29
```

This will list out all the individual IP addresses within that range, which can be helpful for manual scanning or pinpoint targeting.

- Sometimes you need to convert between CIDR notation and netmask for tools that don’t support CIDR:

```
ipcalc 192.168.1.0/24 --netmask
```

This will show you the netmask equivalent of /24, which is 255.255.255.0.

- You can use ipcalc in scripts to automate network reconnaissance. For instance, you could script the tool to generate lists of IP addresses for each subnet in a large network automatically:

```
#!/bin/bash
for subnet in $(ipcalc --split 4 192.168.0.0/16 | grep Network | awk '{print $2}'); do
    echo "Scanning $subnet..."
    nmap -sS $subnet
done
```

Notes: ```awk '{print $2}'```: awk is a powerful text processing tool in Unix/Linux.

```{print $2}'``` tells ```awk``` to print the second field of each line of input. By default, awk splits each line into fields based on whitespace (spaces or tabs).
So, if a line from ipcalc output looks like this:

```
Network:   192.168.0.0/18
```

```$1``` would be "Network:" and ```$2``` would be "192.168.0.0/18". This means the awk command here extracts the subnet part (e.g., "192.168.0.0/18") from each line.

How it all works:

- ipcalc generates subnet information.

- grep filters out the lines containing subnet addresses.

- awk extracts just the subnet addresses.

- The for loop iterates over each subnet, printing a message and then scanning the subnet with nmap.

## Burp Suite with SQLMap

Start by identifying a login page or any form where SQL injection might be possible. Use Burp Suite to intercept and capture the HTTP request as you submit the form with random or suspicious input. This raw request will contain all the necessary data that SQLMap needs for its analysis. Right-click on the captured request in Burp and choose "Save item" to save it as a text file (e.g., request.txt). Use SQLMap to analyze the request by pointing it to the saved file. For example:

```
sqlmap -r request.txt --batch --level=5 --risk=3
```

This command tells SQLMap to read the request from the file, and it applies a more aggressive testing strategy with higher levels of thoroughness.

## smbclient

- Connecting to a Share:

```
smbclient \\\\<target.ip>\\<share_name>
```

Example: ```smbclient \\\\192.168.1.10\\C$```

Navigation Commands:

- List Files/Directories:

```
ls
```

- Move Back a Directory:

```
cd ..
```

Note: *spaces are required after cd commands, unlike in some other shells.*

- Download a File:

```
get <file_name>
```

Upload a File:

```
put <file_name>
```

## redis-cli

- Connect to the Redis Server:

```
redis-cli -h <target.ip>
```

- View Server Information:

```
info
```

- Select a Database:

```
select <db_number>
```

Note: *The default is usually 0, but Redis can have multiple databases (0-15).*

- Lists all keys stored in the selected Redis database:

```
keys *
```

- Retrieves and displays the value associated with the specified key:

```
get <key_name>
```

- Delete a Key:

```
del <key_name>
```

- Set a Value:

```
set <key_name> <value>
```

- Removes all keys from the selected database:

```
flushdb
```

- Returns the type of the specified key (e.g., string, list, set):

```
type <key_name>
```

- Get Detailed Help for a Specific Command:

```
help <command_name>
```

## xfreerdp

- Basic command syntax:

```
xfreerdp /v:<target_IP> /u:<username> /p:<password> [options]
```

- To connect to a remote machine with IP 192.168.1.10, login as Administrator, ignore certificate warnings, and run in full-screen mode:

```
xfreerdp /v:192.168.1.10 /u:Administrator /cert:ignore /f
```

## Gobuster

- Basic Command:

```
sudo gobuster dir -w /usr/share/wordlists/dirb/common.txt -u <target.ip>
```

- Useful Options:

```
-x <extensions>
```

Adds file extensions to the brute-forcing. For example, ```-x php,html``` will check for file.php and file.html.

```
-t <threads>
```

Sets the number of concurrent threads (default is 10). Increasing this number can speed up the scan.

```
-s <status codes>
```

Filters results by HTTP status codes. For instance, ```-s 200,204,301,302``` will show only responses with these status codes.

```
-b <bad codes>
```

Excludes results with these status codes. Example: ```-b 404,403```

- Example Command with Multiple Options:

```
sudo gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://example.com -x php,html -t 50 -s 200,204 -o results.txt
```

This command will scan http://example.com for directories and files using the specified wordlist, check for .php and .html files, use up to 50 threads, only report status codes 200 and 204, and save the results to results.txt.

## MongoDB

To interact with a MongoDB database using the command-line interface:

```
cd mongodb-linux-x86_64-3.4.7/bin
./mongo mongodb://<target_IP>:27017
```

After connecting, use the ```show dbs``` command to list all the databases available on the server:

```
show dbs
```

Use the ```use``` command followed by the database name to switch to a particular database:

```
use <database_name>
```

Within the selected database, use ```show collections``` to list all collections available in the database:

```
show collections
```

Use the ```db.collection.find().pretty()``` command to retrieve and format the documents from a specific collection. Replace ```flag``` with the name of the collection you want to query:

```
db.NAME.find().pretty()
```

Additional Useful MongoDB Commands:

```
db.<collection>.findOne()
```

Retrieves a single document from a collection.

```
db.<collection>.countDocuments()
```

Counts the number of documents in a collection.

```
db.<collection>.drop()
```

Deletes a collection from the database.

```
db.<collection>.remove({})
```

Removes all documents from a collection.

```
db.<collection>.update(<query>, <update>, {upsert: true})
```

Updates documents in a collection, with an option to insert if they don’t exist.

Example: ```db.flag.update({name: "test"}, {$set: {value: "new"}})```

```
db.<collection>.aggregate([<pipeline>])
```

Performs aggregation operations on a collection.

Example: ```db.flag.aggregate([{$match: {status: "active"}}])```

## rsync

- General command structure:

```
rsync [OPTION] ... [USER@]HOST::SRC [DEST]
```

- To list available directories on the target without needing credentials (thanks to anonymous login):

```
rsync --list-only {target_IP}::
```

- After identifying a directory (e.g., "public"), list its contents:

```
rsync --list-only {target_IP}::public
```

- Once you’ve identified the file of interest (e.g., flag.txt), download it to your local machine:

```
rsync {target_IP}::public/flag.txt flag.txt
```

Since the server allowed anonymous access, no credentials were needed.
