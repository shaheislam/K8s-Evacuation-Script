# Kibana Index Grouping Automation Script

## Overview
This repo contains the automation script that transforms the Excel sheet for the 1800+ indexes provided by Kibana to size them accordingly and split them into different sheets. This allows them to be grouped according to specific hubs.

In order to modify the functionality the only changes that need to be made are to the hub dictionary. This will filter for any values for a given key and if found move it over to the Sheet titled with the Key.

e.g EDB: 'edb-banking, edb-logs' , will take any indexes with these strings within them and move them to sheet titled 'EDB'.

The total sizing out the indexes for each key/sheet is given in the terminal at the end, thereby allowing the new spoke elasticsearch cluster deployments to be sized appropriately.



## Prerequisites
You will need:
* Python 3.x.x installed
* The completed Excel CSV file which can be extractd via the Kibana API
* This repo cloned
* Pip installed
* Python 3 installed
* Openpyxl installed using ```pip install openpyxl```

*It is recommended that you do not store the Excel Sheet in the repo directory to avoid accidental file commits.*

## Setup and Execution
1. Execute the script in the directory
    ```python3 index_script.py```

1. Enter the full file path to open when prompted, for example :
    ```/Users/Shahe.Islam/developer/ndap-journey/ndap-journey.xlsx```

1. Enter the full file save path when prompted, for example:
    ```/Users/Shahe.Islam/developer/ndap-journey/ndap-journey-test.xlsx```

4. Once the script has executed, a new Excel spreadsheet will have generated with the additional columns with the tags and size.