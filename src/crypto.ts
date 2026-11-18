/**
 * Cryptocurrency address format recognition and selected public-ledger reads.
 * No wallet-owner attribution, clustering, sanctions clearance, or risk score
 * is inferred without a source-backed screening provider.
 */
export interface CryptoResult {
  address: string;
  blockchain: "Bitcoin" | "Ethereum" | "Solana" | "Tron" | "Litecoin" | "Dogecoin" | "Unknown";
  format: string;
  isValid: boolean; // recognized syntax only; not a checksum or ownership verification
  balance?: string;
  balanceFormatted?: string;
  txCount?: number;
  totalReceived?: string;
  explorerUrl: string;
  entities: {
    names: string[];
    profile_pictures: string[];
    banners: string[];
    usernames: string[];
    emails: string[];
    phones: string[];
    first_seen?: string;
    last_seen?: string;
  };
  platforms: {
    name: string;
    category: string;
    url: string;
    status: "observed" | "inconclusive";
    verified?: boolean;
    confidence?: "high" | "medium" | "low" | "none";
    identifierDisplay?: string;
    fieldsCount?: number;
    extraFields?: Record<string, string>;
    detail: string;
    icon: string;
  }[];
}

export function detectCryptoAddress(address: string): {
  blockchain: CryptoResult["blockchain"];
  format: string;
  isValid: boolean;
  explorerUrl: string;
} {
  const clean = address.trim();
  if (/^0x[a-fA-F0-9]{40}$/.test(clean)) return {
    blockchain: "Ethereum", format: "EVM hexadecimal address pattern (checksum not validated)", isValid: true,
    explorerUrl: `https://etherscan.io/address/${clean}`,
  };
  if (/^bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{39,59}$/i.test(clean) || /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(clean)) return {
    blockchain: "Bitcoin", format: "Bitcoin address pattern (checksum not validated)", isValid: true,
    explorerUrl: `https://blockstream.info/address/${clean}`,
  };
  if (/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(clean)) return {
    blockchain: "Tron", format: "Tron Base58 address pattern (checksum not validated)", isValid: true,
    explorerUrl: `https://tronscan.org/#/address/${clean}`,
  };
  if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(clean)) return {
    blockchain: "Solana", format: "Solana Base58 address pattern (curve validation not performed)", isValid: true,
    explorerUrl: `https://solscan.io/account/${clean}`,
  };
  if (/^(?:[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}|ltc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{39,59})$/i.test(clean)) return {
    blockchain: "Litecoin", format: "Litecoin address pattern (checksum not validated)", isValid: true,
    explorerUrl: `https://blockchair.com/litecoin/address/${clean}`,
  };
  if (/^D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}$/.test(clean)) return {
    blockchain: "Dogecoin", format: "Dogecoin address pattern (checksum not validated)", isValid: true,
    explorerUrl: `https://dogechain.info/address/${clean}`,
  };
  return {
    blockchain: "Unknown", format: "Unrecognized address format", isValid: false,
    explorerUrl: `https://www.blockchain.com/explorer/search?search=${encodeURIComponent(clean)}`,
  };
}

export async function analyzeCrypto(address: string): Promise<CryptoResult> {
  const clean = address.trim();
  const detection = detectCryptoAddress(clean);
  let balance: string | undefined;
  let balanceFormatted: string | undefined;
  let txCount: number | undefined;
  let totalReceived: string | undefined;
  let providerName = "";
  let providerStatus: number | null = null;
  let providerOk = false;

  if (detection.blockchain === "Bitcoin") {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);
      try {
        const res = await fetch(`https://blockstream.info/api/address/${encodeURIComponent(clean)}`, { signal: controller.signal });
        providerStatus = res.status;
        if (res.ok) {
          const data = await res.json() as any;
          const stats = data.chain_stats || {};
          const funded = Number(stats.funded_txo_sum || 0);
          const spent = Number(stats.spent_txo_sum || 0);
          const net = Math.max(0, funded - spent);
          balance = `${(net / 100000000).toFixed(8)} BTC`;
          balanceFormatted = `${balance} (${net.toLocaleString()} satoshis)`;
          txCount = Number(stats.tx_count || 0);
          totalReceived = `${(funded / 100000000).toFixed(8)} BTC`;
          providerName = "Blockstream Bitcoin API";
          providerOk = true;
        }
      } finally { clearTimeout(timer); }
    } catch { /* no provider response; report inconclusive below */ }
  } else if (detection.blockchain === "Ethereum") {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);
      try {
        const call = async (method: string, id: number) => {
          const res = await fetch("https://ethereum-rpc.publicnode.com", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ jsonrpc: "2.0", method, params: [clean, "latest"], id }),
            signal: controller.signal,
          });
          providerStatus = res.status;
          if (!res.ok) throw new Error(`Ethereum RPC HTTP ${res.status}`);
          const data = await res.json() as any;
          if (data.error || typeof data.result !== "string") throw new Error("Ethereum RPC returned no result");
          return data.result as string;
        };
        const [weiHex, nonceHex] = await Promise.all([
          call("eth_getBalance", 1),
          call("eth_getTransactionCount", 2),
        ]);
        const wei = BigInt(weiHex);
        const eth = Number(wei) / 1e18;
        balance = `${eth.toFixed(8)} ETH`;
        balanceFormatted = balance;
        txCount = Number.parseInt(nonceHex, 16);
        providerName = "PublicNode Ethereum JSON-RPC";
        providerOk = true;
      } finally { clearTimeout(timer); }
    } catch { /* no provider response; report inconclusive below */ }
  }

  const platforms: CryptoResult["platforms"] = [{
    name: `${detection.blockchain.toUpperCase()} ADDRESS LOOKUP`,
    category: "Public blockchain data",
    url: detection.explorerUrl,
    status: providerOk ? "observed" : "inconclusive",
    verified: providerOk,
    confidence: providerOk ? "high" : "none",
    identifierDisplay: detection.isValid ? `${detection.blockchain} address format recognized` : "Unrecognized address format",
    fieldsCount: 4,
    extraFields: {
      "Address format": detection.format,
      "Format validation": detection.isValid ? "Pattern only; checksum and ownership not verified" : "Not recognized",
      ...(providerOk ? {
        "Data provider": providerName,
        "Balance": balance || "Not returned",
        "Transaction count": txCount === undefined ? "Not returned" : String(txCount),
        ...(totalReceived ? { "Total received": totalReceived } : {}),
      } : {}),
      ...(providerStatus !== null ? { "Provider HTTP status": String(providerStatus) } : {}),
    },
    detail: providerOk
      ? `The public ledger provider returned address data. On-chain activity does not identify the wallet controller.`
      : detection.isValid
        ? `Address syntax matched a ${detection.blockchain} pattern, but a live ledger response was not obtained. No balance, transaction, owner, cluster, or sanctions conclusion is made.`
        : "The input did not match a supported address pattern.",
    icon: providerOk ? providerName.toLowerCase().replace(/\s+/g, "-") : "blockchain-explorer",
  }];

  return {
    address: clean,
    blockchain: detection.blockchain,
    format: detection.format,
    isValid: detection.isValid,
    balance,
    balanceFormatted,
    txCount,
    totalReceived,
    explorerUrl: detection.explorerUrl,
    entities: {
      names: [], profile_pictures: [], banners: [], usernames: [], emails: [], phones: [],
    },
    platforms,
  };
}
