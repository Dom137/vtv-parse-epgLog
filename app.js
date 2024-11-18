// Load the AWS SDK and required modules
const AWS = require('aws-sdk');
const ProxyAgent = require('proxy-agent').ProxyAgent;
const axios = require('axios');
const https = require('https');

const DEV_MODE = false;



const AIOPS_AUTH_EP = process.env.AIOPS_AUTH_EP;
const AIOPS_AUTH_EP_USER = process.env.AIOPS_AUTH_EP_USER;
const AIOPS_AUTH_EP_PW = process.env.AIOPS_AUTH_EP_PW;

const AIOPS_ALERTS_WEBHOOK_EP = process.env.AIOPS_ALERTS_WEBHOOK_EP;
const AIOPS_TOPO_EP = process.env.AIOPS_TOPO_EP;

const BUCKET_NAME = process.env.AWS_BUCKET_NAME;

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const client = axios.create({
    timeout: 600000,
    maxContentLength: 500 * 1000 * 1000,
    httpsAgent: new https.Agent({ keepAlive: true }),
})

// will be set during runtime based on env var
let USE_PROXY = false;
let PROXY_URL = '';
let s3 = null;
let AIOPS_AUTH_TOKEN = '';
let PARSE_INFO_EVENTS = false;

// helper funciton to convert a string to boolean
async function envStringToBoolean(envVar) {
    return envVar === 'true' || envVar === '1';
}

// function to get the Auth token
async function getAuthToken() {
    try {
        const response = await axios.post(
            AIOPS_AUTH_EP,
            {
                username: AIOPS_AUTH_EP_USER,
                api_key: AIOPS_AUTH_EP_PW
            },
            {
                headers: {
                    'Content-Type': 'application/json',
                },
                proxy: false
            }
        );

        // Extract the token from the response data
        const token = response.data.token;

        // Return the token
        return token;
    } catch (error) {
        console.error('Error:', error.response ? error.response.data : error.message);
    }
}

// Function to send the event object to the HTTP endpoint
async function sendEventsToEndpoint(event) {
    try {
        const response = await client.post(AIOPS_ALERTS_WEBHOOK_EP, event, {
            headers: {
                'Content-Type': 'application/json'
            },
            proxy: false
        });
        console.log(`Successfully sent event to endpoint: ${response.status}`);
    } catch (error) {
        console.log(error);
        console.error(`Failed to send event: ${error}`);
    }
}

// Helper function to introduce a delay
function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function fetchTopologyData(tag) {
    const url = `${AIOPS_TOPO_EP}?_filter=tags%3D${tag}&_limit=10000&_field=name&_field=epgId&_type=channel&_include_global_resources=false&_include_count=false&_include_status=false&_include_status_severity=false&_include_metadata=false&_return_composites=false`;

    try {
        const response = await axios.get(url, {
            headers: {
                'accept': 'application/json',
                'X-TenantID': 'cfd95b7e-3bc7-4006-a4a8-a73a79c71255',
                'Authorization': 'Bearer ' + AIOPS_AUTH_TOKEN
            },
            proxy: false
        });

        if (response.data) {
            // Create a new object with epgId as key and name as value
            const epgIdToNameMap = {};
            response.data._items.forEach(item => {
                epgIdToNameMap[item.epgId] = item.name;
            });
            return epgIdToNameMap;
        }
        else {
            console.error('Error collecting channels from AIOps topology for OPCO:' + tag);
            return null;
        }

    } catch (error) {
        console.log(error);
        console.error('Error fetching topology data:', error.message);
        return null;
    }

}

// Function to parse lines from the file and generate appropriate JSON objects
const parseLogLine = async (line, folderName, topoChannelData) => {
    let event = {};

    if (PARSE_INFO_EVENTS && line.includes("INFO")) {
        // Parse INFO line: [2024-09-05 09:46:25,358] INFO Completed EPG check for channel 5507
        const infoPattern = /\[(.*?)\] INFO Completed EPG check for channel (\d+)/;
        const match = line.match(infoPattern);

        if (match) {
            const epgId = match[2];
            const lookupTag = folderName + '_' + epgId;
            let ressourceIdentifier = lookupTag;
            let channelName = epgId;

            // look up the proper ressource name, identified via Tag <OPCO_EPGID>
            if (topoChannelData && topoChannelData[epgId]) {
                channelName = topoChannelData[epgId];
                ressourceIdentifier = ressourceIdentifier + '_' + channelName;
            }

            event = {
                "event": {
                    "raised": match[1], // Timestamp
                    "ressourceIdentifier": ressourceIdentifier,
                    "message": `Completed EPG check for channel ${channelName}`,
                    "severity": 0, // Severity for INFO
                    "agent": "epg-log-parser",
                    "opco": folderName
                }
            };
            return event;
        }
    } else if (line.includes("ERROR")) {
        // Parse ERROR line: [2024-09-05 09:46:57,039] ERROR No EPG Data for channel: 5457. Date: 2024/09/03. Timeslot: 12-18. EPG Data URL: https://cdn.de.vtv.vodafone.com/epg/5457/2024/09/03/12-18
        const errorPattern = /\[(.*?)\] ERROR No EPG Data for channel: (\d+).+EPG Data URL: (https:\/\/.+)/;
        const match = line.match(errorPattern);

        if (match) {
            const epgId = match[2];
            const lookupTag = folderName + '_' + epgId;
            let ressourceIdentifier = lookupTag;
            let channelName = epgId;

            // look up the prober ressource name, identified via Tag <OPCO_EPGID>
            if (topoChannelData && topoChannelData[epgId]) {
                channelName = topoChannelData[epgId];
                ressourceIdentifier = ressourceIdentifier + '_' + channelName;
            }

            event = {
                "event": {
                    "raised": match[1], // Timestamp
                    "ressourceIdentifier": ressourceIdentifier, // Channel ID
                    "message": `No EPG Data for channel: ${channelName}`,
                    "severity": 4, // Severity for ERROR
                    "agent": "epg-log-parser",
                    "epgUrl": match[3], // EPG Data URL
                    "opco": folderName
                }
            };
            return event;
        }
    }
};


// Function to list all folders (prefixes) and the latest file within each folder, and parse its content
const listFoldersAndParseLatestFiles = async (bucketName) => {

    try {
        // List all folders (prefixes) in the S3 bucket
        const params = {
            Bucket: bucketName,
            Delimiter: '/' // This will make S3 return 'folders' as CommonPrefixes
        };

        const response = await s3.listObjectsV2(params).promise();
        const folders = response.CommonPrefixes;

        if (folders.length === 0) {
            console.log('No folders found in the bucket.');
            return;
        }

        for (const folder of folders) {
            const criticalEventsToSend = [];
            const clearEventsToSend = [];
            const folderPrefix = folder.Prefix;
            const folderName = folderPrefix.slice(0, -1);
            console.log(`Processing folder: ${folderName}`);

            // List all files in the folder
            const folderParams = {
                Bucket: bucketName,
                Prefix: folderPrefix
            };

            const folderResponse = await s3.listObjectsV2(folderParams).promise();
            const files = folderResponse.Contents;

            if (files.length === 0) {
                console.log(`\tNo files found in folder: ${folderPrefix}`);
                continue;
            }

            // Find the latest file in the folder by LastModified date
            const latestFile = files.reduce((latest, current) => {
                return new Date(latest.LastModified) > new Date(current.LastModified) ? latest : current;
            });

            console.log(`\tLatest File: ${latestFile.Key}`);

            // Get the content of the latest file
            const fileParams = {
                Bucket: bucketName,
                Key: latestFile.Key
            };

            const fileData = await s3.getObject(fileParams).promise();
            const fileContent = fileData.Body.toString('utf-8');
            const lines = fileContent.split('\n');

            // get all the topology data for this OPCO:
            const topoChannelData = await fetchTopologyData(folderName);

            // Parse each line of the latest file and generate JSON
            let eventToSend = {};
            await lines.forEach(async line => {
                if (DEV_MODE) {
                    if (folderName == 'DE') {
                        //console.warn('DEBUG-MODE: Only processing data for OPCO <DE>!');
                        const event = await parseLogLine(line, folderName, topoChannelData);
                        if (event && Object.keys(event).length > 0) {
                            if (event.event) {
                                if (event.event.severity > 0) {
                                    criticalEventsToSend.push(event.event);
                                }
                                else if (event.event.severity == 0) {
                                    clearEventsToSend.push(event.event);
                                }
                            }
                        }
                    }
                }
                else {
                    const event = await parseLogLine(line, folderName, topoChannelData);
                    if (event && Object.keys(event).length > 0) {
                        if (event.event.severity) {
                            if (event.event.severity > 0) {
                                criticalEventsToSend.push(event.event);
                            }
                            else {
                                clearEventsToSend.push(event.event);
                            }
                        }
                    }
                }
            });
            const numOfCritEvents = criticalEventsToSend.length;
            const numOfClearEvents = clearEventsToSend.length;
            if (PARSE_INFO_EVENTS && numOfClearEvents > 0) {
                console.log('Clear events: ' + numOfClearEvents);
                eventToSend.events = clearEventsToSend;
                console.log(eventToSend);
                await sendEventsToEndpoint(eventToSend);
            }

            await new Promise(resolve => setTimeout(resolve, 1000));

            if (numOfCritEvents > 0) {
                console.log('Critical events: ' + numOfCritEvents);
                eventToSend.events = criticalEventsToSend;
                //console.log(eventToSend);
                await sendEventsToEndpoint(eventToSend);
            }

            console.log('--------------------------------------------');
        }
    } catch (error) {
        console.error('Error listing folders or files:', error);
    }
};

(async () => {
    try {
        PARSE_INFO_EVENTS = await envStringToBoolean(process.env.PARSE_INFO_EVENTS);
        if(PARSE_INFO_EVENTS){
            console.log("Info events will be processed as per configuration.");
        }
        else {
            console.log("Info events will be ignored as per configuration.");
        }
        console.log("Trying to get Bearer token from AIOps Auth endpoint...");
        AIOPS_AUTH_TOKEN = await getAuthToken();
        let retryCount = 0
        while (retryCount < 3 && AIOPS_AUTH_TOKEN == null) {
            console.warn("Warning: Could not get AIOps Auth token. Retrying...");
            retryCount++;
            await new Promise(resolve => setTimeout(resolve, 1000));
            AIOPS_AUTH_TOKEN = await getAuthToken();
        }
        if (AIOPS_AUTH_TOKEN == null) {
            console.error("ERROR getting AIOps Auth token, retry limit reached! Cannot continue.");
            process.exit(1);
        }
        else {
            console.log("Bearer token from AIOps Auth endpoint received.");
            USE_PROXY = await envStringToBoolean(process.env.APP_USE_PROXY);
            if (USE_PROXY) {
                PROXY_URL = process.env.APP_PROXY_URL;
                const proxyAgent = await new ProxyAgent(PROXY_URL);
                AWS.config.update({
                    httpOptions: { agent: proxyAgent }
                });
                console.log(`Using proxy url <${PROXY_URL}> to access AWS S3 bucket...`);
            }
            else {
                console.log("NOT using proxy to access AWS S3 bucket.");
            }
            s3 = new AWS.S3();
            listFoldersAndParseLatestFiles(BUCKET_NAME);
        }
    } catch (error) {
        console.error('Failed to get AIOps auth token:', error);
    }
})();

