import blessed from "blessed";
import chalk from "chalk";
import figlet from "figlet";
import fs from "fs";
import { HttpsProxyAgent } from "https-proxy-agent";
import { SocksProxyAgent } from "socks-proxy-agent";
import axios from "axios";
import { DirectSecp256k1Wallet } from "@cosmjs/proto-signing";
import { SigningStargateClient, StargateClient, coins } from "@cosmjs/stargate";

const SAFRO_RPC_URL = "https://rpc.testnet.safrochain.com/";
const SAFRO_REST_URL = "https://rest.testnet.safrochain.com/";
const SAFRO_CHAIN_ID = "safro-testnet-1";
const DENOM = "usaf";
const BECH32_PREFIX = "addr_safro";
const CONFIG_FILE = "config.json";
const isDebug = false;

const directions = [
  { chain: "safro", rpc: SAFRO_RPC_URL, chainId: SAFRO_CHAIN_ID }
];

let walletInfo = {
  address: "N/A",
  balanceSAF: "0.0000",
  activeAccount: "N/A"
};
let transactionLogs = [];
let activityRunning = false;
let isCycleRunning = false;
let shouldStop = false;
let dailyActivityInterval = null;
let accounts = [];
let recipients = [];
let proxies = [];
let selectedWalletIndex = 0;
let loadingSpinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const borderBlinkColors = ["cyan", "blue", "magenta", "red", "yellow", "green"];
let borderBlinkIndex = 0;
let blinkCounter = 0;
let spinnerIndex = 0;
let hasLoggedSleepInterrupt = false;
let isHeaderRendered = false;
let activeProcesses = 0;

let dailyActivityConfig = {
  sendRepetitions: 1,
  safSendRange: { min: 1, max: 2 },
  loopHours: 24
};

const userAgents = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"
];

const Headers = {
  'accept': 'application/json',
  'accept-encoding': 'gzip, deflate, br',
  'accept-language': 'en-US,en;q=0.9,id;q=0.8',
  'cache-control': 'no-cache',
  'origin': 'https://hub.safrochain.com',
  'pragma': 'no-cache',
  'priority': 'u=1, i',
  'referer': 'https://hub.safrochain.com/',
  'sec-ch-ua': '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
  'sec-ch-ua-mobile': '?0',
  'sec-ch-ua-platform': '"Windows"',
  'sec-fetch-dest': 'empty',
  'sec-fetch-mode': 'cors',
  'sec-fetch-site': 'same-site',
  'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36'
};

const FaucetHeaders = {
  "accept": "*/*",
  "accept-encoding": "gzip, deflate, br, zstd",
  "accept-language": "en-GB,en-US;q=0.9,en;q=0.8,id;q=0.7,fr;q=0.6,ru;q=0.5,zh-CN;q=0.4,zh;q=0.3",
  "cache-control": "no-cache",
  "content-type": "application/json",
  "origin": "https://faucet.safrochain.com",
  "pragma": "no-cache",
  "priority": "u=1, i",
  "referer": "https://faucet.safrochain.com/",
  "sec-ch-ua": '"Not;A=Brand";v="99", "Opera";v="123", "Chromium";v="139"',
  "sec-ch-ua-mobile": "?0",
  "sec-ch-ua-platform": '"Windows"',
  "sec-fetch-dest": "empty",
  "sec-fetch-mode": "cors",
  "sec-fetch-site": "cross-site",
  "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36 OPR/123.0.0.0 (Edition cdf)"
};

const requestControllers = new Set();

function abortAllRequests() {
  if (requestControllers.size === 0) return;
  addLog(`Aborting ${requestControllers.size} in-flight request(s)...`, "info");
  for (const ctrl of Array.from(requestControllers)) {
    try { ctrl.abort(); } catch (e) {}
    requestControllers.delete(ctrl);
  }
}


function loadConfig() {
  try {
    if (fs.existsSync(CONFIG_FILE)) {
      const data = fs.readFileSync(CONFIG_FILE, "utf8");
      const config = JSON.parse(data);
      dailyActivityConfig.sendRepetitions = Number(config.sendRepetitions) || 1;
      dailyActivityConfig.safSendRange.min = Number(config.safSendRange?.min) || 1;
      dailyActivityConfig.safSendRange.max = Number(config.safSendRange?.max) || 2;
      dailyActivityConfig.loopHours = Number(config.loopHours) || 24;
    } else {
      addLog("No config file found, using default settings.", "info");
    }
  } catch (error) {
    addLog(`Failed to load config: ${error.message}`, "error");
  }
}

function saveConfig() {
  try {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(dailyActivityConfig, null, 2));
    addLog("Configuration saved successfully.", "success");
  } catch (error) {
    addLog(`Failed to save config: ${error.message}`, "error");
  }
}

async function makeApiCall(url, method = "get", data = null, proxyUrl = null, authToken = null, customHeaders = null) {
  const controller = new AbortController();
  requestControllers.add(controller);
  activeProcesses++;

  try {
    const headers = customHeaders ? { ...customHeaders } : { ...Headers };
    headers['user-agent'] = userAgents[Math.floor(Math.random() * userAgents.length)];
    if (authToken) headers['authorization'] = `Bearer ${authToken}`;

    const agent = createAgent(proxyUrl);

    if (isDebug) addLog(`Debug: Sending API request to ${url} payload: ${JSON.stringify(data || {}, null, 2)}`, "debug");

    const response = await axios({
      method,
      url,
      data,
      headers,
      httpsAgent: agent,
      signal: controller.signal,
      timeout: 20000,
      validateStatus: (status) => status >= 200 && status < 500 
    });

    if (isDebug) addLog(`Debug: API response from ${url}: ${JSON.stringify(response.data, null, 2)}`, "debug");

    return response.data;
  } catch (err) {
    const isAbort = err.name === "CanceledError" || err.code === "ERR_CANCELED" || err.message === "canceled";
    if (isAbort) {
      addLog(`Request aborted: ${url}`, "info");
      throw new Error("aborted");
    }
    addLog(`API call failed (${url}): ${err.message}`, "error");
    if (err.response && isDebug) addLog(`Debug: Error response: ${JSON.stringify(err.response.data, null, 2)}`, "debug");
    throw err;
  } finally {
    requestControllers.delete(controller);
    activeProcesses = Math.max(0, activeProcesses - 1);
  }
}


process.on("unhandledRejection", (reason) => {
  addLog(`Unhandled Rejection: ${reason.message || reason}`, "error");
});

process.on("uncaughtException", (error) => {
  addLog(`Uncaught Exception: ${error.message}\n${error.stack}`, "error");
  process.exit(1);
});

function getShortAddress(address) {
  return address ? address.slice(0, 6) + "..." + address.slice(-4) : "N/A";
}

function addLog(message, type = "info") {
  if (type === "debug" && !isDebug) return;
  const timestamp = new Date().toLocaleTimeString("id-ID", { timeZone: "Asia/Jakarta" });
  let coloredMessage;
  switch (type) {
    case "error":
      coloredMessage = chalk.redBright(message);
      break;
    case "success":
      coloredMessage = chalk.greenBright(message);
      break;
    case "warn":
      coloredMessage = chalk.magentaBright(message);
      break;
    case "wait":
      coloredMessage = chalk.yellowBright(message);
      break;
    case "info":
      coloredMessage = chalk.whiteBright(message);
      break;
    case "delay":
      coloredMessage = chalk.cyanBright(message);
      break;
    case "debug":
      coloredMessage = chalk.blueBright(message);
      break;
    default:
      coloredMessage = chalk.white(message);
  }
  const logMessage = `[${timestamp}] ${coloredMessage}`;
  transactionLogs.push(logMessage);
  updateLogs();
}

function getShortHash(hash) {
  return hash.slice(0, 6) + "..." + hash.slice(-4);
}

function clearTransactionLogs() {
  transactionLogs = [];
  logBox.setContent('');
  logBox.scrollTo(0);
  addLog("Transaction logs cleared.", "success");
}

async function loadAccounts() {
  try {
    const data = fs.readFileSync("pk.txt", "utf8");
    const privateKeys = data.split("\n").map(line => line.trim()).filter(line => line);
    accounts = await Promise.all(privateKeys.map(async (privateKeyHex) => {
      const privateKeyBytes = Buffer.from(privateKeyHex, 'hex');
      const wallet = await DirectSecp256k1Wallet.fromKey(privateKeyBytes, BECH32_PREFIX);
      const [acc] = await wallet.getAccounts();
      return { privateKey: privateKeyHex, address: acc.address, token: null };
    }));
    if (accounts.length === 0) {
      throw new Error("No private keys found in pk.txt");
    }
    addLog(`Loaded ${accounts.length} accounts from pk.txt`, "success");
  } catch (error) {
    addLog(`Failed to load accounts: ${error.message}`, "error");
    accounts = [];
  }
}

function loadRecipients() {
  try {
    if (fs.existsSync("wallet.txt")) {
      const data = fs.readFileSync("wallet.txt", "utf8");
      recipients = data.split("\n").map(addr => addr.trim()).filter(addr => addr);
      if (recipients.length === 0) throw new Error("No recipient addresses found in wallet.txt");
      addLog(`Loaded ${recipients.length} recipients from wallet.txt`, "success");
    } else {
      throw new Error("wallet.txt not found");
    }
  } catch (error) {
    addLog(`Failed to load recipients: ${error.message}`, "error");
    recipients = [];
  }
}

function loadProxies() {
  try {
    if (fs.existsSync("proxy.txt")) {
      const data = fs.readFileSync("proxy.txt", "utf8");
      proxies = data.split("\n").map(proxy => proxy.trim()).filter(proxy => proxy);
      if (proxies.length === 0) throw new Error("No proxy found in proxy.txt");
      addLog(`Loaded ${proxies.length} proxies from proxy.txt`, "success");
    } else {
      addLog("No proxy.txt found, running without proxy.", "info");
    }
  } catch (error) {
    addLog(`Failed to load proxy: ${error.message}`, "info");
    proxies = [];
  }
}

function createAgent(proxyUrl) {
  if (!proxyUrl) return null;
  if (proxyUrl.startsWith("socks")) {
    return new SocksProxyAgent(proxyUrl);
  } else {
    return new HttpsProxyAgent(proxyUrl);
  }
}

async function getQueryClient() {
  return await StargateClient.connect(SAFRO_RPC_URL);
}

async function sleep(ms) {
  if (shouldStop) {
    if (!hasLoggedSleepInterrupt) {
      addLog("Process stopped successfully.", "info");
      hasLoggedSleepInterrupt = true;
    }
    return;
  }
  activeProcesses++;
  try {
    await new Promise((resolve) => {
      const timeout = setTimeout(() => {
        resolve();
      }, ms);
      const checkStop = setInterval(() => {
        if (shouldStop) {
          clearTimeout(timeout);
          clearInterval(checkStop);
          if (!hasLoggedSleepInterrupt) {
            addLog("Process interrupted.", "info");
            hasLoggedSleepInterrupt = true;
          }
          resolve();
        }
      }, 100);
    });
  } catch (error) {
    addLog(`Sleep error: ${error.message}`, "error");
  } finally {
    activeProcesses = Math.max(0, activeProcesses - 1);
  }
}

async function updateWalletData() {
  const queryClient = await getQueryClient();
  const walletDataPromises = accounts.map(async (account, i) => {
    try {
      const balance = await queryClient.getBalance(account.address, DENOM);
      const formattedSAF = (Number(balance.amount) / 1e6).toFixed(6);

      const formattedEntry = `${i === selectedWalletIndex ? "→ " : "  "}${chalk.bold.magentaBright(getShortAddress(account.address))}        ${chalk.bold.cyanBright(formattedSAF.padEnd(12))}`;

      if (i === selectedWalletIndex) {
        walletInfo.address = account.address;
        walletInfo.activeAccount = `Account ${i + 1}`;
        walletInfo.balanceSAF = formattedSAF;
      }
      return formattedEntry;
    } catch (error) {
      addLog(`Failed to fetch wallet data for account #${i + 1}: ${error.message}`, "error");
      return `${i === selectedWalletIndex ? "→ " : "  "}N/A 0.000000`;
    }
  });
  try {
    const walletData = await Promise.all(walletDataPromises);
    addLog("Wallet data updated.", "success");
    return walletData;
  } catch (error) {
    addLog(`Wallet data update failed: ${error.message}`, "error");
    return [];
  }
}

async function performLogin(address, proxyUrl) {
  const url = "https://api-safrochainhub.safrochain.com/api/v1/auth";
  const payload = { address };
  const response = await makeApiCall(url, "post", payload, proxyUrl);
  if (response.status && response.data.token && response.data.token.token) {
    addLog(`Login successful for ${getShortAddress(address)}`, "success");
    return response.data.token.token;
  } else {
    throw new Error("Login failed");
  }
}

async function performClaimFaucet(address, proxyUrl) {
  const url = "https://faucetapi.safrochain.com/api/transaction";
  const payload = { receiver: address };
  let retries = 0;
  const maxRetries = 6;
  while (retries < maxRetries) {
    if (shouldStop) throw new Error("stopped");
    try {
      const response = await makeApiCall(url, "post", payload, proxyUrl, null, FaucetHeaders);
      if (response && (response.success || response.status === true)) {
        addLog(`Faucet claimed successfully for ${getShortAddress(address)}, Hash: ${getShortHash(response.transactionHash || (response.hash || ''))}`, "success");
        return response;
      } else {
        throw new Error(response?.error || response?.message || "Faucet claim failed");
      }
    } catch (error) {
      if (error.message === "aborted" || error.message === "stopped") {
        throw error;
      }
      if (error.message.includes("Rate limit exceeded")) {
        addLog(`Faucet claim failed due to rate limit: ${error.message}.`, "error");
        throw error; 
      }
      addLog(`Faucet claim attempt ${retries + 1} failed: ${error.message}`, "error");
      retries++;
      if (shouldStop) throw new Error("stopped");
      await sleep(5000);
    }
  }
  throw new Error("Faucet claim failed after max retries");
}
async function performSend(privateKeyHex, fromAddress, toAddress, amount, proxyUrl) {
  if (shouldStop) throw new Error("stopped");
  activeProcesses++;
  let client = null;
  try {
    const privateKeyBytes = Buffer.from(privateKeyHex, 'hex');
    const wallet = await DirectSecp256k1Wallet.fromKey(privateKeyBytes, BECH32_PREFIX);
    if (shouldStop) throw new Error("stopped");

    client = await SigningStargateClient.connectWithSigner(SAFRO_RPC_URL, wallet);

    if (shouldStop) throw new Error("stopped");

    const balance = await client.getBalance(fromAddress, DENOM);
    const available = Number(balance.amount) / 1e6;
    if (available < amount + 0.03) {
      throw new Error(`Insufficient SAF balance: ${available} < ${amount} + fee`);
    }

    const amountU = (amount * 1e6).toFixed(0);
    const msg = {
      typeUrl: "/cosmos.bank.v1beta1.MsgSend",
      value: {
        fromAddress,
        toAddress,
        amount: [{ denom: DENOM, amount: amountU }]
      },
    };

    const fee = {
      amount: coins(40000, DENOM),
      gas: "200000",
    };

    const memo = "Sent via Safrochain Hub";

    if (shouldStop) throw new Error("stopped");

    const result = await client.signAndBroadcast(fromAddress, [msg], fee, memo);

    if (result.code !== 0) {
      throw new Error(`Tx failed: ${result.rawLog || JSON.stringify(result)}`);
    }

    addLog(`Send ${amount} SAF to ${getShortAddress(toAddress)} successful, Hash: ${getShortHash(result.transactionHash || (result.txhash || ''))}`, "success");
    return result;
  } finally {
    activeProcesses = Math.max(0, activeProcesses - 1);
    try {
      if (client && typeof client.disconnect === "function") client.disconnect();
    } catch (e) {}
  }
}

async function reportTransaction(fromAddr, toAddr, amount, hash, block_height, token, proxyUrl, type = "send", validator_addr = null, fee = 0.001) {
  const url = "https://api-safrochainhub.safrochain.com/api/v1/transactions";
  const payload = {
    type,
    from_addr: fromAddr,
    to_addr: toAddr,
    amount: parseFloat(amount),
    description: "Sent via Safrochain Hub",
    memo: "Sent via Safrochain Hub",
    hash,
    block_height,
    confirmations: 0,
    status: 1,
    fee
  };
  const response = await makeApiCall(url, "post", payload, proxyUrl, token);
  if (response.status) {
    addLog(`Transaction reported successfully for hash ${getShortHash(hash)}`, "success");
  } else {
    throw new Error("Report failed");
  }
}

async function fetchAllMissions(token, proxyUrl) {
  let missions = [];
  let page = 1;
  let lastPage = 1;
  do {
    const url = `https://api-safrochainhub.safrochain.com/api/v1/public/missions?onChain=true&page=${page}&perPage=10`;
    const response = await makeApiCall(url, "get", null, proxyUrl, token);
    if (response.status) {
      missions = missions.concat(response.data.data);
      lastPage = response.data.meta.lastPage;
      page++;
    } else {
      throw new Error("Failed to fetch missions");
    }
  } while (page <= lastPage);
  return missions;
}

async function completeMission(missionId, token, proxyUrl) {
  const url = `https://api-safrochainhub.safrochain.com/api/v1/do/missions/${missionId}`;
  const response = await makeApiCall(url, "post", {}, proxyUrl, token);
  return response;
}

async function getUserPoints(token, proxyUrl) {
  const url = "https://api-safrochainhub.safrochain.com/api/v1/me";
  const response = await makeApiCall(url, "get", null, proxyUrl, token);
  if (response.status) {
    return response.data.point;
  } else {
    throw new Error("Failed to fetch user points");
  }
}

async function processMissions(token, proxyUrl) {
  if (shouldStop) return;
  let missions = [];
  try {
    missions = await fetchAllMissions(token, proxyUrl);
  } catch (err) {
    addLog(`Failed to fetch missions: ${err.message}`, "error");
    return;
  }

  await sleep(10000);
  for (const mission of missions) {
    if (shouldStop) break;
    const status = mission.user_mission_status || "not_started";
    if (status === "not_started" || status === "rejected") {
      try {
        if (shouldStop) break;
        const response = await completeMission(mission.id, token, proxyUrl);
        if (response && response.status) {
          const missionStatus = response.data.status;
          if (missionStatus === "completed") {
            addLog(`Mission ${mission.name} Completed Successfully`, "success");
          } else if (missionStatus === "pending_verification") {
            addLog(`Mission ${mission.name} pending verification`, "warn");
          } else {
            addLog(`Mission ${mission.name} status: ${missionStatus}`, "info");
          }
        } else {
          addLog(`Failed to complete mission ${mission.name}: ${response?.message || 'unknown'}`, "error");
        }
      } catch (error) {
        if (error.message === "aborted" || error.message === "stopped") {
          break;
        }
        addLog(`Error completing mission ${mission.name}: ${error.message}`, "error");
      }
    } else if (status === "completed") {
      addLog(`Mission ${mission.name} Already Completed`, "wait");
    } else if (status === "pending_verification") {
      addLog(`Mission ${mission.name} is pending verification`, "warn");
    }

    const delay = Math.floor(Math.random() * (8000 - 5000 + 1)) + 5000;
    await sleep(delay);
    if (shouldStop) break;
  }

  try {
    if (!shouldStop) {
      const points = await getUserPoints(token, proxyUrl);
      addLog(`Total user points: ${points}`, "success");
    }
  } catch (error) {
    if (error.message !== "aborted" && error.message !== "stopped") {
      addLog(`Failed to get user points: ${error.message}`, "error");
    }
  }
}

async function runDailyActivity() {
  if (accounts.length === 0) {
    addLog("No valid accounts found.", "error");
    return;
  }
  if (recipients.length === 0) {
    addLog("No valid recipients found.", "error");
    return;
  }
  addLog(`Starting daily activity for all accounts. Auto Send: ${dailyActivityConfig.sendRepetitions}x`, "info");
  activityRunning = true;
  isCycleRunning = true;
  shouldStop = false;
  hasLoggedSleepInterrupt = false;
  activeProcesses = Math.max(0, activeProcesses);
  updateMenu();
  try {
    for (let accountIndex = 0; accountIndex < accounts.length && !shouldStop; accountIndex++) {
      addLog(`Starting processing for account ${accountIndex + 1}`, "info");
      selectedWalletIndex = accountIndex;
      const proxyUrl = proxies[accountIndex % proxies.length] || null;
      addLog(`Account ${accountIndex + 1}: Using Proxy ${proxyUrl || "none"}`, "info");
      const { privateKey, address } = accounts[accountIndex];
      if (!address.startsWith(BECH32_PREFIX)) {
        addLog(`Invalid wallet address for account ${accountIndex + 1}: ${address}`, "error");
        continue;
      }
      addLog(`Processing account ${accountIndex + 1}: ${getShortAddress(address)}`, "wait");

      try {
        const token = await performLogin(address, proxyUrl);
        accounts[accountIndex].token = token;
        if (shouldStop) return; 
      } catch (error) {
        addLog(`Account ${accountIndex + 1} - Login failed: ${error.message}. Skipping account.`, "error");
        continue;
      }

      addLog(`Account ${accountIndex + 1} - Waiting 10 seconds Before Claim Faucet...`, "delay");
      await sleep(10000);

      addLog(`Account ${accountIndex + 1} - Claiming faucet...`, "info");
      try {
        const faucetResult = await performClaimFaucet(address, proxyUrl);
        await updateWallets();
        if (shouldStop) return;
      } catch (error) {
        addLog(`Account ${accountIndex + 1} - Faucet claim failed: ${error.message}`, "error");
      }

      addLog(`Account ${accountIndex + 1} - Waiting 10 seconds Before Auto Send...`, "delay");
      await sleep(10000);

      const direction = directions[0];
      for (let sendCount = 0; sendCount < dailyActivityConfig.sendRepetitions && !shouldStop; sendCount++) {
        let amount = (Math.random() * (dailyActivityConfig.safSendRange.max - dailyActivityConfig.safSendRange.min) + dailyActivityConfig.safSendRange.min).toFixed(4);
        if (amount < 1) amount = 1;
        const toAddress = recipients[Math.floor(Math.random() * recipients.length)];
        addLog(`Account ${accountIndex + 1} - Send ${sendCount + 1}: ${amount} SAF to ${getShortAddress(toAddress)}`, "warn");
        try {
          const result = await performSend(privateKey, address, toAddress, parseFloat(amount), proxyUrl);
          const hash = result.transactionHash;
          const block_height = result.height || 0;
          await reportTransaction(address, toAddress, amount, hash, block_height, accounts[accountIndex].token, proxyUrl);
          if (shouldStop) return;

        } catch (error) {
          addLog(`Account ${accountIndex + 1} - Send ${sendCount + 1}: Failed: ${error.message}. Skipping to next.`, "error");
        } finally {
          await updateWallets();
        }
        if (sendCount < dailyActivityConfig.sendRepetitions - 1 && !shouldStop) {
          const randomDelay = Math.floor(Math.random() * (15000 - 10000 + 1)) + 10000;
          addLog(`Account ${accountIndex + 1} - Waiting ${Math.floor(randomDelay / 1000)} seconds before next send...`, "delay");
          await sleep(randomDelay);
          if (shouldStop) return;

        }
      }

      addLog(`Account ${accountIndex + 1} - Waiting 10 seconds before processing missions...`, "delay");
      await sleep(10000);
      addLog(`Account ${accountIndex + 1} - Processing on-chain missions...`, "info");
      await processMissions(accounts[accountIndex].token, proxyUrl);
      if (shouldStop) return;
      if (accountIndex < accounts.length - 1 && !shouldStop) {
        addLog(`Waiting 10 seconds before next account...`, "delay");
        await sleep(10000);
      }
    }
    if (!shouldStop && activeProcesses <= 0) {
      addLog(`All accounts processed. Waiting ${dailyActivityConfig.loopHours} hours for next cycle.`, "success");
      dailyActivityInterval = setTimeout(runDailyActivity, dailyActivityConfig.loopHours * 60 * 60 * 1000);
    }
  } catch (error) {
    addLog(`Daily activity failed: ${error.message}`, "error");
  } finally {
    if (shouldStop) {
      if (activeProcesses <= 0) {
        if (dailyActivityInterval) {
          clearTimeout(dailyActivityInterval);
          dailyActivityInterval = null;
          addLog("Cleared daily activity interval.", "info");
        }
        activityRunning = false;
        isCycleRunning = false;
        shouldStop = false;
        hasLoggedSleepInterrupt = false;
        activeProcesses = 0;
        addLog("Daily activity stopped successfully.", "success");
        updateMenu();
        updateStatus();
        safeRender();
      } else {
        const stopCheckInterval = setInterval(() => {
          if (activeProcesses <= 0) {
            clearInterval(stopCheckInterval);
            if (dailyActivityInterval) {
              clearTimeout(dailyActivityInterval);
              dailyActivityInterval = null;
              addLog("Cleared daily activity interval.", "info");
            }
            activityRunning = false;
            isCycleRunning = false;
            shouldStop = false;
            hasLoggedSleepInterrupt = false;
            activeProcesses = 0;
            addLog("Daily activity stopped successfully.", "success");
            updateMenu();
            updateStatus();
            safeRender();
          } else {
            addLog(`Waiting for ${activeProcesses} process to complete...`, "info");
          }
        }, 1000);
      }
    } else {
      activityRunning = false;
      isCycleRunning = activeProcesses > 0 || dailyActivityInterval !== null;
      updateMenu();
      updateStatus();
      safeRender();
    }
  }
}

const screen = blessed.screen({
  smartCSR: true,
  title: "SAFROCHAIN AUTO BOT",
  autoPadding: true,
  fullUnicode: true,
  mouse: true,
  ignoreLocked: ["C-c", "q", "escape"]
});

const headerBox = blessed.box({
  top: 0,
  left: "center",
  width: "100%",
  height: 6,
  tags: true,
  style: { fg: "yellow", bg: "default" }
});

const statusBox = blessed.box({
  left: 0,
  top: 6,
  width: "100%",
  height: 3,
  tags: true,
  border: { type: "line", fg: "cyan" },
  style: { fg: "white", bg: "default", border: { fg: "cyan" } },
  content: "Status: Initializing...",
  padding: { left: 1, right: 1, top: 0, bottom: 0 },
  label: chalk.cyan(" Status "),
  wrap: true
});

const walletBox = blessed.list({
  label: " Wallet Information",
  top: 9,
  left: 0,
  width: "40%",
  height: "35%",
  border: { type: "line", fg: "cyan" },
  style: { border: { fg: "cyan" }, fg: "white", bg: "default", item: { fg: "white" } },
  scrollable: true,
  scrollbar: { bg: "cyan", fg: "black" },
  padding: { left: 1, right: 1, top: 0, bottom: 0 },
  tags: true,
  keys: true,
  vi: true,
  mouse: true,
  content: "Loading wallet data..."
});

const logBox = blessed.log({
  label: " Transaction Logs",
  top: 9,
  left: "41%",
  width: "59%",
  height: "100%-9",
  border: { type: "line" },
  scrollable: true,
  alwaysScroll: true,
  mouse: true,
  tags: true,
  scrollbar: { ch: "│", style: { bg: "cyan", fg: "white" }, track: { bg: "gray" } },
  scrollback: 100,
  smoothScroll: true,
  style: { border: { fg: "magenta" }, bg: "default", fg: "white" },
  padding: { left: 1, right: 1, top: 0, bottom: 0 },
  wrap: true,
  focusable: true,
  keys: true
});

const menuBox = blessed.list({
  label: " Menu ",
  top: "44%",
  left: 0,
  width: "40%",
  height: "56%",
  keys: true,
  vi: true,
  mouse: true,
  border: { type: "line" },
  style: { fg: "white", bg: "default", border: { fg: "red" }, selected: { bg: "magenta", fg: "black" }, item: { fg: "white" } },
  items: isCycleRunning
    ? ["Stop Activity", "Set Manual Config", "Clear Logs", "Refresh", "Exit"]
    : ["Start Auto Daily Activity", "Set Manual Config", "Clear Logs", "Refresh", "Exit"],
  padding: { left: 1, top: 1 }
});

const dailyActivitySubMenu = blessed.list({
  label: " Manual Config Options ",
  top: "44%",
  left: 0,
  width: "40%",
  height: "56%",
  keys: true,
  vi: true,
  mouse: true,
  border: { type: "line" },
  style: {
    fg: "white",
    bg: "default",
    border: { fg: "blue" },
    selected: { bg: "blue", fg: "black" },
    item: { fg: "white" }
  },
  items: [
    "Set Send Repetitions",
    "Set SAF Send Range",
    "Set Loop Daily",
    "Back to Main Menu"
  ],
  padding: { left: 1, top: 1 },
  hidden: true
});

const configForm = blessed.form({
  label: " Enter Config Value ",
  top: "center",
  left: "center",
  width: "30%",
  height: "40%",
  keys: true,
  mouse: true,
  border: { type: "line" },
  style: {
    fg: "white",
    bg: "default",
    border: { fg: "blue" }
  },
  padding: { left: 1, top: 1 },
  hidden: true
});

const minLabel = blessed.text({
  parent: configForm,
  top: 0,
  left: 1,
  content: "Min Value:",
  style: { fg: "white" }
});

const maxLabel = blessed.text({
  parent: configForm,
  top: 4,
  left: 1,
  content: "Max Value:",
  style: { fg: "white" }
});

const configInput = blessed.textbox({
  parent: configForm,
  top: 1,
  left: 1,
  width: "90%",
  height: 3,
  inputOnFocus: true,
  border: { type: "line" },
  style: {
    fg: "white",
    bg: "default",
    border: { fg: "white" },
    focus: { border: { fg: "green" } }
  }
});

const configInputMax = blessed.textbox({
  parent: configForm,
  top: 5,
  left: 1,
  width: "90%",
  height: 3,
  inputOnFocus: true,
  border: { type: "line" },
  style: {
    fg: "white",
    bg: "default",
    border: { fg: "white" },
    focus: { border: { fg: "green" } }
  }
});

const configSubmitButton = blessed.button({
  parent: configForm,
  top: 9,
  left: "center",
  width: 10,
  height: 3,
  content: "Submit",
  align: "center",
  border: { type: "line" },
  clickable: true,
  keys: true,
  mouse: true,
  style: {
    fg: "white",
    bg: "blue",
    border: { fg: "white" },
    hover: { bg: "green" },
    focus: { bg: "green", border: { fg: "yellow" } }
  }
});

screen.append(headerBox);
screen.append(statusBox);
screen.append(walletBox);
screen.append(logBox);
screen.append(menuBox);
screen.append(dailyActivitySubMenu);
screen.append(configForm);

let renderQueue = [];
let isRendering = false;
function safeRender() {
  renderQueue.push(true);
  if (isRendering) return;
  isRendering = true;
  setTimeout(() => {
    try {
      if (!isHeaderRendered) {
        figlet.text("NT EXHAUST", { font: "ANSI Shadow" }, (err, data) => {
          if (!err) headerBox.setContent(`{center}{bold}{cyan-fg}${data}{/cyan-fg}{/bold}{/center}`);
          isHeaderRendered = true;
        });
      }
      screen.render();
    } catch (error) {
      addLog(`UI render error: ${error.message}`, "error");
    }
    renderQueue.shift();
    isRendering = false;
    if (renderQueue.length > 0) safeRender();
  }, 100);
}

function adjustLayout() {
  const screenHeight = screen.height || 24;
  const screenWidth = screen.width || 80;
  headerBox.height = Math.max(6, Math.floor(screenHeight * 0.15));
  statusBox.top = headerBox.height;
  statusBox.height = Math.max(3, Math.floor(screenHeight * 0.07));
  statusBox.width = screenWidth - 2;
  walletBox.top = headerBox.height + statusBox.height;
  walletBox.width = Math.floor(screenWidth * 0.4);
  walletBox.height = Math.floor(screenHeight * 0.35);
  logBox.top = headerBox.height + statusBox.height;
  logBox.left = Math.floor(screenWidth * 0.41);
  logBox.width = screenWidth - walletBox.width - 2;
  logBox.height = screenHeight - (headerBox.height + statusBox.height);
  menuBox.top = headerBox.height + statusBox.height + walletBox.height;
  menuBox.width = Math.floor(screenWidth * 0.4);
  menuBox.height = screenHeight - (headerBox.height + statusBox.height + walletBox.height);

  if (menuBox.top != null) {
    dailyActivitySubMenu.top = menuBox.top;
    dailyActivitySubMenu.width = menuBox.width;
    dailyActivitySubMenu.height = menuBox.height;
    dailyActivitySubMenu.left = menuBox.left;
    configForm.width = Math.floor(screenWidth * 0.3);
    configForm.height = Math.floor(screenHeight * 0.4);
  }

  safeRender();
}

function updateStatus() {
  try {
    const isProcessing = activityRunning || (isCycleRunning && dailyActivityInterval !== null);
    const status = activityRunning
      ? `${loadingSpinner[spinnerIndex]} ${chalk.yellowBright("Running")}`
      : isCycleRunning && dailyActivityInterval !== null
      ? `${loadingSpinner[spinnerIndex]} ${chalk.yellowBright("Waiting for next cycle")}`
      : chalk.green("Idle");
    const statusText = `Status: ${status} | Active Account: ${getShortAddress(walletInfo.address)} | Total Accounts: ${accounts.length} | Auto Send: ${dailyActivityConfig.sendRepetitions}x | Loop: ${dailyActivityConfig.loopHours}h | SAFROCHAIN AUTO BOT`;
    statusBox.setContent(statusText);
    if (isProcessing) {
      if (blinkCounter % 1 === 0) {
        statusBox.style.border.fg = borderBlinkColors[borderBlinkIndex];
        borderBlinkIndex = (borderBlinkIndex + 1) % borderBlinkColors.length;
      }
      blinkCounter++;
    } else {
      statusBox.style.border.fg = "cyan";
    }
    spinnerIndex = (spinnerIndex + 1) % loadingSpinner.length;
    safeRender();
  } catch (error) {
    addLog(`Status update error: ${error.message}`, "error");
  }
}

async function updateWallets() {
  try {
    const walletData = await updateWalletData();
    const header = `${chalk.bold.cyan("  Address").padEnd(20)}               ${chalk.bold.cyan("SAF".padEnd(12))}`;
    const separator = chalk.gray("-".repeat(80));
    walletBox.setItems([header, separator, ...walletData]);
    walletBox.select(0);
    safeRender();
  } catch (error) {
    addLog(`Failed to update wallet data: ${error.message}`, "error");
  }
}

function updateLogs() {
  try {
    logBox.add(transactionLogs[transactionLogs.length - 1] || chalk.gray("No logs available."));
    logBox.scrollTo(transactionLogs.length);
    safeRender();
  } catch (error) {
    addLog(`Log update failed: ${error.message}`, "error");
  }
}

function updateMenu() {
  try {
    menuBox.setItems(
      isCycleRunning
        ? ["Stop Activity", "Set Manual Config", "Clear Logs", "Refresh", "Exit"]
        : ["Start Auto Daily Activity", "Set Manual Config", "Clear Logs", "Refresh", "Exit"]
    );
    safeRender();
  } catch (error) {
    addLog(`Menu update failed: ${error.message}`, "error");
  }
}

const statusInterval = setInterval(updateStatus, 100);

logBox.key(["up"], () => {
  if (screen.focused === logBox) {
    logBox.scroll(-1);
    safeRender();
  }
});

logBox.key(["down"], () => {
  if (screen.focused === logBox) {
    logBox.scroll(1);
    safeRender();
  }
});

logBox.on("click", () => {
  screen.focusPush(logBox);
  logBox.style.border.fg = "yellow";
  menuBox.style.border.fg = "red";
  dailyActivitySubMenu.style.border.fg = "blue";
  safeRender();
});

logBox.on("blur", () => {
  logBox.style.border.fg = "magenta";
  safeRender();
});

menuBox.on("select", async (item) => {
  const action = item.getText();
  switch (action) {
    case "Start Auto Daily Activity":
      if (isCycleRunning) {
        addLog("Cycle is still running. Stop the current cycle first.", "error");
      } else {
        await runDailyActivity();
      }
      break;
    case "Stop Activity":
  shouldStop = true;
  if (dailyActivityInterval) {
    clearTimeout(dailyActivityInterval);
    dailyActivityInterval = null;
    addLog("Cleared daily activity interval.", "info");
  }

  abortAllRequests();

  addLog("Stopping daily activity. Please wait for ongoing process to complete.", "info");
  safeRender();

  if (activeProcesses <= 0) {
    activityRunning = false;
    isCycleRunning = false;
    shouldStop = false;
    hasLoggedSleepInterrupt = false;
    activeProcesses = 0;
    addLog("Daily activity stopped successfully.", "success");
    updateMenu();
    updateStatus();
    safeRender();
  } else {
    const stopCheckInterval = setInterval(() => {
      if (activeProcesses <= 0) {
        clearInterval(stopCheckInterval);
        if (dailyActivityInterval) { clearTimeout(dailyActivityInterval); dailyActivityInterval = null; addLog("Cleared daily activity interval.", "info"); }
        activityRunning = false;
        isCycleRunning = false;
        shouldStop = false;
        hasLoggedSleepInterrupt = false;
        activeProcesses = 0;
        addLog("Daily activity stopped successfully.", "success");
        updateMenu();
        updateStatus();
        safeRender();
      } else {
        addLog(`Waiting for ${activeProcesses} process(es) to complete...`, "info");
      }
    }, 1000);
  }
  break;
    case "Set Manual Config":
      menuBox.hide();
      dailyActivitySubMenu.show();
      setTimeout(() => {
        if (dailyActivitySubMenu.visible) {
          screen.focusPush(dailyActivitySubMenu);
          dailyActivitySubMenu.style.border.fg = "yellow";
          logBox.style.border.fg = "magenta";
          safeRender();
        }
      }, 100);
      break;
    case "Clear Logs":
      clearTransactionLogs();
      break;
    case "Refresh":
      await updateWallets();
      addLog("Data refreshed.", "success");
      break;
    case "Exit":
      clearInterval(statusInterval);
      process.exit(0);
  }
});

dailyActivitySubMenu.on("select", (item) => {
  const action = item.getText();
  switch (action) {
    case "Set Send Repetitions":
      configForm.configType = "sendRepetitions";
      configForm.setLabel(" Enter Send Repetitions ");
      minLabel.hide();
      maxLabel.hide();
      configInput.setValue(dailyActivityConfig.sendRepetitions.toString());
      configInputMax.setValue("");
      configInputMax.hide();
      configForm.show();
      setTimeout(() => {
        if (configForm.visible) {
          screen.focusPush(configInput);
          configInput.clearValue();
          safeRender();
        }
      }, 100);
      break;
    case "Set SAF Send Range":
      configForm.configType = "safSendRange";
      configForm.setLabel(" Enter SAF Send Range (Min >=1) ");
      minLabel.show();
      maxLabel.show();
      configInput.setValue(dailyActivityConfig.safSendRange.min.toString());
      configInputMax.setValue(dailyActivityConfig.safSendRange.max.toString());
      configInputMax.show();
      configForm.show();
      setTimeout(() => {
        if (configForm.visible) {
          screen.focusPush(configInput);
          configInput.clearValue();
          safeRender();
        }
      }, 100);
      break;
    case "Set Loop Daily":
      configForm.configType = "loopHours";
      configForm.setLabel(" Enter Loop Hours (Min 1 Hours) ");
      minLabel.hide();
      maxLabel.hide();
      configInput.setValue(dailyActivityConfig.loopHours.toString());
      configInputMax.setValue("");
      configInputMax.hide();
      configForm.show();
      setTimeout(() => {
        if (configForm.visible) {
          screen.focusPush(configInput);
          configInput.clearValue();
          safeRender();
        }
      }, 100);
      break;
    case "Back to Main Menu":
      dailyActivitySubMenu.hide();
      menuBox.show();
      setTimeout(() => {
        if (menuBox.visible) {
          screen.focusPush(menuBox);
          menuBox.style.border.fg = "cyan";
          dailyActivitySubMenu.style.border.fg = "blue";
          logBox.style.border.fg = "magenta";
          safeRender();
        }
      }, 100);
      break;
  }
});

let isSubmitting = false;
configForm.on("submit", () => {
  if (isSubmitting) return;
  isSubmitting = true;

  const inputValue = configInput.getValue().trim();
  let value, maxValue;
  try {
    if (configForm.configType === "loopHours" || configForm.configType === "sendRepetitions") {
      value = parseInt(inputValue);
    } else {
      value = parseFloat(inputValue);
    }
    if (["safSendRange"].includes(configForm.configType)) {
      maxValue = parseFloat(configInputMax.getValue().trim());
      if (isNaN(maxValue) || maxValue <= 0) {
        addLog("Invalid Max value. Please enter a positive number.", "error");
        configInputMax.clearValue();
        screen.focusPush(configInputMax);
        safeRender();
        isSubmitting = false;
        return;
      }
    }
    if (isNaN(value) || value <= 0) {
      addLog("Invalid input. Please enter a positive number.", "error");
      configInput.clearValue();
      screen.focusPush(configInput);
      safeRender();
      isSubmitting = false;
      return;
    }
    if (configForm.configType === "loopHours" && value < 1) {
      addLog("Invalid input. Minimum is 1 hour.", "error");
      configInput.clearValue();
      screen.focusPush(configInput);
      safeRender();
      isSubmitting = false;
      return;
    }
    if (configForm.configType === "safSendRange" && value < 1) {
      addLog("Invalid Min value. Minimum is 1 SAF.", "error");
      configInput.clearValue();
      screen.focusPush(configInput);
      safeRender();
      isSubmitting = false;
      return;
    }
  } catch (error) {
    addLog(`Invalid format: ${error.message}`, "error");
    configInput.clearValue();
    screen.focusPush(configInput);
    safeRender();
    isSubmitting = false;
    return;
  }

  if (configForm.configType === "sendRepetitions") {
    dailyActivityConfig.sendRepetitions = Math.floor(value);
    addLog(`Send Repetitions set to ${dailyActivityConfig.sendRepetitions}`, "success");
  } else if (configForm.configType === "safSendRange") {
    if (value > maxValue) {
      addLog("Min value cannot be greater than Max value.", "error");
      configInput.clearValue();
      configInputMax.clearValue();
      screen.focusPush(configInput);
      safeRender();
      isSubmitting = false;
      return;
    }
    dailyActivityConfig.safSendRange.min = value;
    dailyActivityConfig.safSendRange.max = maxValue;
    addLog(`SAF Send Range set to ${value} - ${maxValue}`, "success");
  } else if (configForm.configType === "loopHours") {
    dailyActivityConfig.loopHours = value;
    addLog(`Loop Daily set to ${value} hours`, "success");
  }
  saveConfig();
  updateStatus();

  configForm.hide();
  dailyActivitySubMenu.show();
  setTimeout(() => {
    if (dailyActivitySubMenu.visible) {
      screen.focusPush(dailyActivitySubMenu);
      dailyActivitySubMenu.style.border.fg = "yellow";
      logBox.style.border.fg = "magenta";
      safeRender();
    }
    isSubmitting = false;
  }, 100);
});

configInput.key(["enter"], () => {
  if (["safSendRange"].includes(configForm.configType)) {
    screen.focusPush(configInputMax);
  } else {
    configForm.submit();
  }
});

configInputMax.key(["enter"], () => {
  configForm.submit();
});

configSubmitButton.on("press", () => {
  configForm.submit();
});

configSubmitButton.on("click", () => {
  screen.focusPush(configSubmitButton);
  configForm.submit();
});

configForm.key(["escape"], () => {
  configForm.hide();
  dailyActivitySubMenu.show();
  setTimeout(() => {
    if (dailyActivitySubMenu.visible) {
      screen.focusPush(dailyActivitySubMenu);
      dailyActivitySubMenu.style.border.fg = "yellow";
      logBox.style.border.fg = "magenta";
      safeRender();
    }
  }, 100);
});

dailyActivitySubMenu.key(["escape"], () => {
  dailyActivitySubMenu.hide();
  menuBox.show();
  setTimeout(() => {
    if (menuBox.visible) {
      screen.focusPush(menuBox);
      menuBox.style.border.fg = "cyan";
      dailyActivitySubMenu.style.border.fg = "blue";
      logBox.style.border.fg = "magenta";
      safeRender();
    }
  }, 100);
});

screen.key(["escape", "q", "C-c"], () => {
  addLog("Exiting application", "info");
  clearInterval(statusInterval);
  process.exit(0);
});

async function initialize() {
  try {
    loadConfig();
    await loadAccounts();
    loadRecipients();
    loadProxies();
    updateStatus();
    await updateWallets();
    updateLogs();
    safeRender();
    menuBox.focus();
  } catch (error) {
    addLog(`Initialization error: ${error.message}`, "error");
  }
}

setTimeout(() => {
  adjustLayout();
  screen.on("resize", adjustLayout);
}, 100);


initialize();
