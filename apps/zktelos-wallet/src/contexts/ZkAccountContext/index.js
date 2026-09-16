import React, {createContext, useState, useEffect, useCallback, useContext, useMemo} from 'react';
import {ethers, BigNumber} from 'ethers';
import AES from 'crypto-js/aes';
import Utf8 from 'crypto-js/enc-utf8';
import * as Sentry from "@sentry/react";
import {
  TxDepositDeadlineExpiredError, ClientState,
  HistoryRecordState, HistoryTransactionType,
  deriveSpendingKeyZkBob,
  ZkBobClient,
} from 'zkbob-client-js';
import {ProverMode} from 'zkbob-client-js/lib/config';
import {toast} from 'react-toastify';
import {Trans} from 'react-i18next';

import {
  TransactionModalContext, ModalContext, PoolContext,
  TokenBalanceContext, SupportIdContext, WalletContext,
} from 'contexts';

import {TX_STATUSES} from 'constants';
import {showLoadingError} from 'utils';
import {usePrevious} from 'hooks';
import config from 'config';

import zp from './zp.js';
import {aggregateFees, splitDirectDeposits} from './utils.js';

// Expose tools globally
window.deriveSpendingKeyZkBob = deriveSpendingKeyZkBob;
window.deriveSpendingKey = deriveSpendingKeyZkBob;
window.ZkBobClient = ZkBobClient;
window.zkConfig = config;

const ZkAccountContext = createContext({zkAccount: null});

const defaultLimits = {
  singleDepositLimit: null,
  singleDirectDepositLimit: null,
  dailyDepositLimitPerAddress: null,
  dailyDirectDepositLimitPerAddress: null,
  dailyDepositLimit: null,
  dailyWithdrawalLimit: null,
  poolSizeLimit: null,
};

export default ZkAccountContext;

export const ZkAccountContextProvider = ({children}) => {
  const {currentPool, setCurrentPool} = useContext(PoolContext);
  const previousPoolAlias = usePrevious(currentPool.alias);
  const {
    address: account, currentChainId, switchNetwork,
    signMessageAsync, signTypedDataAsync, sendTransactionAsync,
  } = useContext(WalletContext);
  const {openTxModal, setTxStatus, setTxAmount, setTxError} = useContext(TransactionModalContext);
  const {openPasswordModal, closeAllModals} = useContext(ModalContext);
  const {updateBalance: updateTokenBalance} = useContext(TokenBalanceContext);
  const {supportId, updateSupportId} = useContext(SupportIdContext);
  // Multi-pool state: store zkClients, balances, histories per pool alias
  const [zkClients, setZkClients] = useState({});
  const [zkAccount, setZkAccount] = useState(null);
  const [balances, setBalances] = useState({});
  const [histories, setHistories] = useState({});
  const [isPendingIncomingByPool, setIsPendingIncomingByPool] = useState({});
  const [isPendingByPool, setIsPendingByPool] = useState({});
  const [pendingActionsByPool, setPendingActionsByPool] = useState({});
  const [isPoolSwitching, setIsPoolSwitching] = useState(false);
  const [isLoadingZkAccount, setIsLoadingZkAccount] = useState(false);
  const [isLoadingState, setIsLoadingState] = useState(false);
  const [isLoadingHistory, setIsLoadingHistory] = useState(false);
  const [isLoadingLimits, setIsLoadingLimits] = useState(false);
  const [limitsByPool, setLimitsByPool] = useState({});
  const [minTxAmountByPool, setMinTxAmountByPool] = useState({});
  const [loadingPercentage, setLoadingPercentage] = useState(null);
  const [relayerVersion, setRelayerVersion] = useState(null);
  const [isDemo] = useState(false);
  const [giftCard, setGiftCard] = useState(null);
  const [giftCardTxHash, setGiftCardTxHash] = useState(null);
  const [pendingDirectDepositsByPool, setPendingDirectDepositsByPool] = useState({});

  // Computed values for the active pool
  const zkClient = useMemo(() => zkClients[currentPool.alias] || null, [zkClients, currentPool.alias]);

  // Expose to window for console/external scripts
  useEffect(() => {
    window.zkClient = zkClient;
    window.deriveSpendingKeyZkBob = deriveSpendingKeyZkBob;
  }, [zkClient]);
  const balance = useMemo(() => balances[currentPool.alias] || ethers.constants.Zero, [balances, currentPool.alias]);
  const history = useMemo(() => histories[currentPool.alias] || [], [histories, currentPool.alias]);
  const isPendingIncoming = useMemo(() => isPendingIncomingByPool[currentPool.alias] || false, [isPendingIncomingByPool, currentPool.alias]);
  const isPending = useMemo(() => isPendingByPool[currentPool.alias] || false, [isPendingByPool, currentPool.alias]);
  const pendingActions = useMemo(() => pendingActionsByPool[currentPool.alias] || [], [pendingActionsByPool, currentPool.alias]);
  const limits = useMemo(() => limitsByPool[currentPool.alias] || defaultLimits, [limitsByPool, currentPool.alias]);
  const minTxAmount = useMemo(() => minTxAmountByPool[currentPool.alias] || ethers.constants.Zero, [minTxAmountByPool, currentPool.alias]);
  const pendingDirectDeposits = useMemo(() => pendingDirectDepositsByPool[currentPool.alias] || [], [pendingDirectDepositsByPool, currentPool.alias]);

  function updateLoadingPercentage(state, progress) {
    if (state === ClientState.StateUpdatingContinuous) {
      setLoadingPercentage(progress);
    } else {
      setLoadingPercentage(null);
    }
  }

  useEffect(() => {
    // Create all zkClients in parallel if not already created of the pools belonging to the default chain.
    const defaultPool = config.pools[config.defaultPool];
    const defaultChainId = defaultPool.chainId;
    const poolAliases = Object.keys(config.pools).filter(alias => config.pools[alias].chainId === defaultChainId);
    const allClientsExist = poolAliases.every(alias => zkClients[alias]);
    if (allClientsExist || !supportId) return;

    async function createClients() {
      try {
        // Create all clients in parallel
        const clientPromises = poolAliases.map(async (alias) => {
          if (zkClients[alias]) return {alias, client: zkClients[alias]};
          const client = await zp.createClient(alias, updateLoadingPercentage);
          return {alias, client};
        });

        const results = await Promise.all(clientPromises);

        // Build the zkClients object
        const newZkClients = {};
        results.forEach(({alias, client}) => {
          newZkClients[alias] = client;
        });

        setZkClients(newZkClients);
      } catch (error) {
        console.error(error);
        Sentry.captureException(error, {tags: {method: 'ZkAccountContext.createZkClients'}});
        showLoadingError('zkClient');
      }
    }
    createClients();
  }, [supportId, zkClients]);

  const loadZkAccount = useCallback(async (secretKey, birthIndex) => {
    setZkAccount(null);
    const poolAliases = Object.keys(zkClients);
    const allClientsReady = poolAliases.length > 0 && poolAliases.every(alias => zkClients[alias]);

    if (allClientsReady && secretKey) {
      // Initialize balances and histories for all pools
      const initialBalances = {};
      const initialHistories = {};
      poolAliases.forEach(alias => {
        initialBalances[alias] = ethers.constants.Zero;
        initialHistories[alias] = [];
      });
      setBalances(initialBalances);
      setHistories(initialHistories);
      setIsLoadingZkAccount(true);

      try {
        // Login to all zkClients in parallel with the same secretKey
        const loginPromises = poolAliases.map(async (alias) => {
          await zp.createAccount(zkClients[alias], secretKey, birthIndex);
        });
        await Promise.all(loginPromises);

        const zkAccount = ethers.utils.id(secretKey);
        setZkAccount(zkAccount);
      } catch (error) {
        console.error(error);
        Sentry.captureException(error, {tags: {method: 'ZkAccountContext.loadZkAccount'}});
        showLoadingError('zkAccount');
      }
    }
    setIsLoadingZkAccount(false);
  }, [zkClients]);

  const shieldedAmountToWei = async (client, shieldedAmount) => {
    if (!client) return BigNumber.from(0);
    const wei = await client.shieldedAmountToWei(shieldedAmount);
    return BigNumber.from(wei);
  };

  const fromShieldedAmount = useCallback(async shieldedAmount => {
    return shieldedAmountToWei(zkClient, shieldedAmount);
  }, [zkClient]);

  const toShieldedAmount = useCallback(wei => {
    if (!zkClient) return BigInt(0);
    return zkClient.weiToShieldedAmount(wei.toBigInt());
  }, [zkClient]);

  const updateBalance = useCallback(async (poolAlias = currentPool.alias) => {
    let balance = ethers.constants.Zero;
    const client = zkClients[poolAlias];
    if (zkAccount && client) {
      setIsLoadingState(true);
      try {
        balance = await client.getTotalBalance();
        balance = await shieldedAmountToWei(client, balance);
      } catch (error) {
        console.error(error);
        Sentry.captureException(error, {tags: {method: 'ZkAccountContext.updateBalance', pool: poolAlias}});
        showLoadingError('zkAccountBalance');
      }
    }
    setBalances(prev => ({...prev, [poolAlias]: balance}));
    setIsLoadingState(false);
  }, [zkAccount, zkClients, currentPool.alias]);

  const updateHistory = useCallback(async (poolAlias = currentPool.alias) => {
    let history = [];
    let isPendingIncoming = false;
    let isPending = false;
    let pendingActions = [];
    const client = zkClients[poolAlias];

    if (zkAccount && client) {
      if (poolAlias !== previousPoolAlias) {
        setHistories(prev => ({...prev, [poolAlias]: []}));
        setIsPendingIncomingByPool(prev => ({...prev, [poolAlias]: false}));
        setIsPendingByPool(prev => ({...prev, [poolAlias]: false}));
        setPendingActionsByPool(prev => ({...prev, [poolAlias]: []}));
      }
      setIsLoadingHistory(true);
      try {
        history = await client.getAllHistory();
        history = await Promise.all(history.map(async item => ({
          ...item,
          failed: [HistoryRecordState.RejectedByRelayer, HistoryRecordState.RejectedByPool].includes(item.state),
          actions: await Promise.all(item.actions.map(async action => ({
            ...action,
            amount: await shieldedAmountToWei(client, action.amount)
          }))),
          fee: await shieldedAmountToWei(client, item.fee),
        })));
        history = splitDirectDeposits(history);
        history = aggregateFees(history);
        history = history.reverse();
        isPendingIncoming = !!history.find(item =>
          item.state === HistoryRecordState.Pending && item.type === HistoryTransactionType.TransferIn
        );
        const poolConfig = config.pools[poolAlias];
        pendingActions = history
          .filter(item => item.state === HistoryRecordState.Pending && item.type !== HistoryTransactionType.TransferIn)
          .map(item => ({...item, poolAlias, pool: poolConfig}));
        isPending = pendingActions.length > 0;
      } catch (error) {
        console.error(error);
        Sentry.captureException(error, {tags: {method: 'ZkAccountContext.updateHistory', pool: poolAlias}});
        showLoadingError('history');
      }
    }
    setHistories(prev => ({...prev, [poolAlias]: history}));
    setPendingActionsByPool(prev => ({...prev, [poolAlias]: pendingActions}));
    setIsPendingByPool(prev => ({...prev, [poolAlias]: isPending}));
    setIsPendingIncomingByPool(prev => ({...prev, [poolAlias]: isPendingIncoming}));
    setIsLoadingHistory(false);
  }, [zkAccount, zkClients, currentPool.alias, previousPoolAlias]);

  const updatePendingDirectDeposits = useCallback(async (poolAlias = currentPool.alias) => {
    let pendingDirectDeposits = [];
    const client = zkClients[poolAlias];
    if (zkAccount && client) {
      try {
        pendingDirectDeposits = await client.getPendingDDs();
        pendingDirectDeposits = await Promise.all(pendingDirectDeposits.map(async item => ({
          ...item,
          type: HistoryTransactionType.DirectDeposit,
          actions: [{
            to: item.destination,
            amount: await shieldedAmountToWei(client, item.amount),
          }],
          fee: await shieldedAmountToWei(client, item.fee),
        })));
      } catch (error) {
        console.error(error);
        Sentry.captureException(error, {tags: {method: 'ZkAccountContext.updatePendingDirectDeposits', pool: poolAlias}});
      }
    }
    setPendingDirectDepositsByPool(prev => ({...prev, [poolAlias]: pendingDirectDeposits}));
  }, [zkAccount, zkClients, currentPool.alias]);


  const updateLimits = useCallback(async (poolAlias = currentPool.alias) => {
    const client = zkClients[poolAlias];
    if (!zkAccount || !client) return;
    setIsLoadingLimits(true);
    let limits = defaultLimits;
    try {
      const data = await client.getLimits(account);
      limits = {
        singleDepositLimit: await shieldedAmountToWei(client, BigInt(data.deposit.components.singleOperation)),
        singleDirectDepositLimit: await shieldedAmountToWei(client, BigInt(data.dd.components.singleOperation)),
        dailyDepositLimitPerAddress: {
          total: await shieldedAmountToWei(client, BigInt(data.deposit.components.dailyForAddress.total)),
          available: await shieldedAmountToWei(client, BigInt(data.deposit.components.dailyForAddress.available))
        },
        dailyDirectDepositLimitPerAddress: {
          total: await shieldedAmountToWei(client, BigInt(data.dd.components.dailyForAddress.total)),
          available: await shieldedAmountToWei(client, BigInt(data.dd.components.dailyForAddress.available))
        },
        dailyDepositLimit: {
          total: await shieldedAmountToWei(client, BigInt(data.deposit.components.dailyForAll.total)),
          available: await shieldedAmountToWei(client, BigInt(data.deposit.components.dailyForAll.available))
        },
        dailyWithdrawalLimit: {
          total: await shieldedAmountToWei(client, BigInt(data.withdraw.components.dailyForAll.total)),
          available: await shieldedAmountToWei(client, BigInt(data.withdraw.components.dailyForAll.available))
        },
        poolSizeLimit: {
          total: await shieldedAmountToWei(client, BigInt(data.deposit.components.poolLimit.total)),
          available: await shieldedAmountToWei(client, BigInt(data.deposit.components.poolLimit.available))
        },
      };
    } catch (error) {
      console.error(error);
      Sentry.captureException(error, {tags: {method: 'ZkAccountContext.updateLimits', pool: poolAlias}});
      showLoadingError('limits');
    }
    setLimitsByPool(prev => ({...prev, [poolAlias]: limits}));
    setIsLoadingLimits(false);
  }, [zkAccount, zkClients, account, currentPool.alias]);

  const calcMaxTransferable = useCallback(async (type, relayerFee, amountToConvert = ethers.constants.Zero) => {
    let max = ethers.constants.Zero;
    if (zkAccount) {
      try {
        const amountToConvertShielded = await toShieldedAmount(amountToConvert);
        max = await zkClient.calcMaxAvailableTransfer(type, relayerFee, amountToConvertShielded, false);
        max = await fromShieldedAmount(max);
      } catch (error) {
        console.error(error);
        Sentry.captureException(error, {tags: {method: 'ZkAccountContext.calcMaxTransferable'}});
      }
    }
    return max;
  }, [zkAccount, zkClient, fromShieldedAmount, toShieldedAmount]);

  const loadMinTxAmount = useCallback(async (poolAlias = currentPool.alias) => {
    let minTxAmount = ethers.constants.Zero;
    const client = zkClients[poolAlias];
    if (zkAccount && client) {
      try {
        minTxAmount = await client.minTxAmount();
        minTxAmount = await shieldedAmountToWei(client, minTxAmount);
      } catch (error) {
        console.error(error);
        Sentry.captureException(error, {tags: {method: 'ZkAccountContext.loadMinTxAmount', pool: poolAlias}});
      }
    }
    setMinTxAmountByPool(prev => ({...prev, [poolAlias]: minTxAmount}));
  }, [zkAccount, zkClients, currentPool.alias]);

  const loadRelayerVersion = useCallback(async () => {
    if (!zkClient) return;
    let version = null;
    try {
      // const data = await zkClient.getRelayerVersion();
      version = "TODO";
    } catch (error) {
      console.error(error);
      Sentry.captureException(error, {tags: {method: 'ZkAccountContext.loadRelayerVersion'}});
    }
    setRelayerVersion(version);
  }, [zkClient]);

  const updatePoolData = useCallback((poolAlias = currentPool.alias) => Promise.all([
    updateBalance(poolAlias),
    updateHistory(poolAlias),
    updateLimits(poolAlias),
    updatePendingDirectDeposits(poolAlias),
  ]), [updateBalance, updateHistory, updateLimits, updatePendingDirectDeposits, currentPool.alias]);

  const switchToPool = useCallback(async poolId => {
    const targetClient = zkClients[poolId];
    if (!targetClient) return;

    setIsPoolSwitching(true);
    try {
      // Switch the currentPool context - this will update all computed values
      setCurrentPool(poolId);

      // Load data for the new pool
      if (zkAccount) {
        await updatePoolData(poolId);
      }
    } catch (error) {
      console.error('Error switching pool:', error);
      Sentry.captureException(error, {tags: {method: 'ZkAccountContext.switchToPool', targetPool: poolId}});
    } finally {
      setIsPoolSwitching(false);
    }
  }, [zkClients, setCurrentPool, zkAccount, updatePoolData]);

  const deposit = useCallback(async (amount, relayerFee, isNative) => {
    openTxModal();
    setTxAmount(amount);
    const activeClient = zkClients[currentPool.alias];
    try {
      if (currentChainId !== currentPool.chainId) {
        setTxStatus(TX_STATUSES.SWITCH_NETWORK);
        try {
          await switchNetwork({ chainId: currentPool.chainId });
        } catch (error) {
          console.error(error);
          Sentry.captureException(error, {tags: {method: 'ZkAccountContext.deposit.switchNetwork', pool: currentPool.alias}});
          setTxStatus(TX_STATUSES.WRONG_NETWORK);
          return;
        }
      }
      const shieldedAmount = await toShieldedAmount(amount);
      if (isNative) {
        await zp.directDeposit(account, sendTransactionAsync, activeClient, shieldedAmount, setTxStatus);
      } else {
        await zp.deposit(account, signMessageAsync, signTypedDataAsync, activeClient, shieldedAmount, relayerFee, setTxStatus);
      }
      updatePoolData(currentPool.alias);
      setTimeout(updateTokenBalance, 5000);
    } catch (error) {
      console.error(error);
      Sentry.captureException(error, {tags: {method: 'ZkAccountContext.deposit', pool: currentPool.alias}});
      let message = error?.message;
      if (error instanceof TxDepositDeadlineExpiredError) {
        setTxStatus(TX_STATUSES.SIGNATURE_EXPIRED);
      } else if (message?.includes('Internal account validation failed')) {
        setTxStatus(TX_STATUSES.SUSPICIOUS_ACCOUNT_DEPOSIT);
      } else {
        if (
          error?.code === 4001 ||
          error?.code === 'ACTION_REJECTED' ||
          message?.includes('user rejected transaction') ||
          message?.includes('User denied transaction signature')
        ) {
          message = 'User rejected transaction.';
        } else if (
          message?.includes('user rejected signing') ||
          message?.includes('User denied message signature')
        ) {
          message = 'User rejected message signing.';
        }
        setTxError(message);
        setTxStatus(TX_STATUSES.REJECTED);
      }
    }
  }, [
    zkClients, updatePoolData, signTypedDataAsync, openTxModal, setTxAmount,
    setTxStatus, updateTokenBalance, toShieldedAmount, setTxError,
    currentChainId, switchNetwork, currentPool, sendTransactionAsync, account, signMessageAsync,
  ]);

  const transfer = useCallback(async (to, amount, relayerFee, memo = '') => {
    openTxModal();
    const activeClient = zkClients[currentPool.alias];
    try {
      setTxAmount(amount);
      const shieldedAmount = await toShieldedAmount(amount);
      await zp.transfer(activeClient, [{destination: to, amountGwei: shieldedAmount}], relayerFee, setTxStatus, false, memo);
      updatePoolData(currentPool.alias);
    } catch (error) {
      console.error(error);
      Sentry.captureException(error, {tags: {method: 'ZkAccountContext.transfer', pool: currentPool.alias}});
      setTxError(error.message);
      setTxStatus(TX_STATUSES.REJECTED);
    }
  }, [
    zkClients, updatePoolData, openTxModal, setTxError,
    setTxStatus, toShieldedAmount, setTxAmount, currentPool.alias,
  ]);

  const transferMulti = useCallback(async (data, relayerFee, memos = {}) => {
    openTxModal();
    const activeClient = zkClients[currentPool.alias];
    try {
      setTxAmount(data.reduce((acc, curr) => acc.add(curr.amount), ethers.constants.Zero));
      const transfers = await Promise.all(data.map(async ({address, amount}) => ({
        destination: address,
        amountGwei: await toShieldedAmount(amount)
      })));
      await zp.transfer(activeClient, transfers, relayerFee, setTxStatus, true, memos);
      updatePoolData(currentPool.alias);
    } catch (error) {
      console.error(error);
      Sentry.captureException(error, {tags: {method: 'ZkAccountContext.transferMulti', pool: currentPool.alias}});
      setTxError(error.message);
      setTxStatus(TX_STATUSES.REJECTED);
    }
  }, [
    zkClients, updatePoolData, openTxModal, setTxError,
    setTxStatus, toShieldedAmount, setTxAmount, currentPool.alias,
  ]);

  const withdraw = useCallback(async (to, amount, amountToConvert, relayerFee) => {
    openTxModal();
    setTxAmount(amount);
    const activeClient = zkClients[currentPool.alias];
    try {
      const shieldedAmount = await toShieldedAmount(amount);
      const shieldedAmountToConvert = await toShieldedAmount(amountToConvert);
      await zp.withdraw(activeClient, to, shieldedAmount, shieldedAmountToConvert, relayerFee, setTxStatus);
      updatePoolData(currentPool.alias);
      setTimeout(updateTokenBalance, 5000);
    } catch (error) {
      console.error(error);
      Sentry.captureException(error, {tags: {method: 'ZkAccountContext.withdraw', pool: currentPool.alias}});
      if (error?.message?.includes('Internal account validation failed')) {
        setTxStatus(TX_STATUSES.SUSPICIOUS_ACCOUNT_WITHDRAWAL);
      } else {
        setTxError(error.message);
        setTxStatus(TX_STATUSES.REJECTED);
      }
    }
  }, [
    zkClients, updatePoolData, openTxModal, setTxAmount, setTxError,
    setTxStatus, updateTokenBalance, toShieldedAmount, currentPool.alias,
  ]);

  const generateAddress = useCallback(() => {
    if (!zkAccount) return;
    return zkClient.generateAddress();
  }, [zkAccount, zkClient]);

  const verifyShieldedAddress = useCallback(address => {
    if (!zkAccount) return false;
    return zkClient.verifyShieldedAddress(address);
  }, [zkClient, zkAccount]);

  const verifyShieldedAddressWithPoolInfo = useCallback(async (address) => {
    if (!zkAccount || !address) {
      return {isValid: false, poolInfo: null};
    }

    try {
      const isValid = await zkClient.verifyShieldedAddress(address);
      if (isValid) {
        return {isValid: true, poolInfo: null};
      }
    } catch (error) {
      console.debug('Address verification failed for current pool:', error);
    }

    const poolAliases = Object.keys(config.pools);

    for (const alias of poolAliases) {
      if (alias === currentPool.alias) continue;

      const client = zkClients[alias];
      if (!client) continue;

      try {
        const isValidForPool = await client.verifyShieldedAddress(address);
        if (isValidForPool) {
          const pool = config.pools[alias];
          return {isValid: false, poolInfo: {alias, tokenSymbol: pool.tokenSymbol || alias}};
        }
      } catch (err) {
        console.debug(`Could not verify address for pool ${alias}:`, err);
      }
    }

    return {isValid: false, poolInfo: null};
  }, [zkAccount, zkClient, zkClients, currentPool.alias]);

  const estimateFee = useCallback(async (amounts, txType, amountToConvert = ethers.constants.Zero) => {
    if (!zkClient) return null;
    try {
      let directDepositFee = ethers.constants.Zero;
      try {
        directDepositFee = await fromShieldedAmount(await zkClient.directDepositFee());
      } catch (error) {
        if (!error?.message?.includes('No direct deposit processer initialized')) throw error;
      }
      if (!zkAccount) {
        let atomicTxFee = await zkClient.atomicTxFee(txType);
        atomicTxFee = await fromShieldedAmount(atomicTxFee.total);
        return {fee: atomicTxFee, numberOfTxs: 1, insufficientFunds: false, directDepositFee};
      }
      const shieldedAmounts = await Promise.all(amounts.map(async amount => await toShieldedAmount(amount)));
      const shieldedAmountToConvert = await toShieldedAmount(amountToConvert);
      const {
        fee,
        txCnt,
        insufficientFunds,
        relayerFee,
      } = await zkClient.feeEstimate(shieldedAmounts, txType, shieldedAmountToConvert, false);
      return {
        fee: await fromShieldedAmount(fee.total),
        numberOfTxs: txCnt,
        insufficientFunds,
        relayerFee,
        directDepositFee,
      };
    } catch (error) {
      console.error(error);
      Sentry.captureException(error, {tags: {method: 'ZkAccountContext.estimateFee'}});
      return null;
    }
  }, [zkClient, toShieldedAmount, fromShieldedAmount, zkAccount]);

  const initializeGiftCard = useCallback(async code => {
    if (!zkClient) return false;
    const parsed = await zkClient.giftCardFromCode(code);
    parsed.parsedBalance = await fromShieldedAmount(parsed.balance);
    setGiftCard(parsed);
    return true;
  }, [zkClient, fromShieldedAmount]);

  const deleteGiftCard = () => setGiftCard(null);

  const redeemGiftCard = useCallback(async () => {
    try {
      if (currentPool.alias !== giftCard.poolAlias) {
        await switchToPool(giftCard.poolAlias);
      }
      const jobId = await zkClient.redeemGiftCard(
        giftCard,
        ProverMode.Local,
      );
      const txHash = await zkClient.waitJobTxHash(jobId);
      setGiftCardTxHash(txHash);
      deleteGiftCard();
      updatePoolData();
    } catch (error) {
      console.error(error);
      Sentry.captureException(error, {tags: {method: 'ZkAccountContext.redeemGiftCard'}});
      throw error;
    }
  }, [zkClient, giftCard, switchToPool, currentPool, updatePoolData]);

  const getSeed = () => {
    const seed = window.localStorage.getItem('seed');
    const hasPassword = !ethers.utils.isValidMnemonic(seed);
    return {seed, hasPassword};
  };

  const decryptMnemonic = useCallback(password => {
    const {seed} = getSeed();
    const mnemonic = AES.decrypt(seed, password).toString(Utf8);
    if (!ethers.utils.isValidMnemonic(mnemonic)) throw new Error('invalid mnemonic');
    return mnemonic;
  }, []);

  const unlockAccount = useCallback(async password => {
    if (!zkClient) return false;
    try {
      const mnemonic = decryptMnemonic(password);
      // closePasswordModal();
      await loadZkAccount(mnemonic);
      return true;
    } catch (error) {
      throw new Error('Incorrect password');
    }
  }, [zkClient, loadZkAccount, decryptMnemonic]);

  const verifyPassword = useCallback(password => {
    try {
      decryptMnemonic(password);
      return true;
    } catch (error) {
      return false;
    }
  }, [decryptMnemonic]);

  const setPassword = useCallback(password => {
    const {seed, hasPassword} = getSeed();
    if (hasPassword) {
      console.error('Password already set');
      return;
    }
    const cipherText = AES.encrypt(seed, password).toString();
    window.localStorage.setItem('seed', cipherText);
  }, []);

  const removePassword = useCallback(password => {
    const mnemonic = decryptMnemonic(password);
    window.localStorage.setItem('seed', mnemonic);
  }, [decryptMnemonic]);

  const saveZkAccountMnemonic = useCallback((mnemonic, password, isNewAccount) => {
    let seed = mnemonic;
    if (password) {
      seed = AES.encrypt(mnemonic, password).toString();
    }
    window.localStorage.setItem('seed', seed);
    loadZkAccount(mnemonic, isNewAccount ? -1 : undefined);
  }, [loadZkAccount]);

  const clearState = useCallback(() => {
    setZkAccount(null);
    setBalances({});
    setHistories({});
    updateSupportId();
  }, [updateSupportId]);

  const removeZkAccountMnemonic = useCallback(async () => {
    const clientsToLogout = zkAccount ? Object.values(zkClients).filter(Boolean) : [];

    window.localStorage.removeItem('seed');
    clearState();

    for (const client of clientsToLogout) {
      try {
        await client.cleanState();
        await client.logout();
      } catch (error) {
        console.warn('Error during client cleanup:', error);
      }
    }
  }, [zkAccount, zkClients, clearState]);

  const lockAccount = useCallback(() => {
    const {seed, hasPassword} = getSeed();
    if (seed) {
      closeAllModals();
      if (hasPassword) {
        clearState();
        openPasswordModal();
      } else {
        updateSupportId();
      }
    }
  }, [openPasswordModal, clearState, closeAllModals, updateSupportId]);

  useEffect(() => {
    if (!zkAccount) return;
    updatePoolData();
  }, [updatePoolData, currentPool, zkAccount]);

  // Load data for all pools when zkAccount is set (after login)
  useEffect(() => {
    if (!zkAccount) return;

    const poolAliases = Object.keys(config.pools);

    // Update all pools in parallel (balance, history, limits, pending deposits, minTxAmount)
    Promise.all(poolAliases.map(poolAlias =>
      Promise.all([
        updatePoolData(poolAlias),
        loadMinTxAmount(poolAlias)
      ])
    ))
      .catch(error => {
        console.error('[ZkAccountContext] Error loading pools data:', error);
      });
  }, [zkAccount]); // eslint-disable-line react-hooks/exhaustive-deps
  // Note: updatePoolData and loadMinTxAmount are intentionally omitted to only trigger on login/logout

  useEffect(() => {
    if (!zkAccount) return;
    loadMinTxAmount();
  }, [loadMinTxAmount, currentPool, zkAccount]);

  useEffect(() => {
    if (!zkAccount) return;
    if (isPending || isPendingIncoming || giftCardTxHash || pendingDirectDeposits.length > 0) {
      if (giftCardTxHash) {
        const tx = history.find(item => item.txHash === giftCardTxHash);
        if (tx && tx.state !== HistoryRecordState.Pending) {
          setGiftCardTxHash(null);
          toast.success(
            <span>
              <b><Trans i18nKey="successNotification.title" /></b><br />
              <Trans i18nKey="successNotification.description" />
            </span>
          );
        }
      }
      const interval = (isPending || isPendingIncoming || giftCardTxHash) ? 5000 : 30000; // 5 seconds or 30 seconds
      const intervalId = setInterval(() => {
        updatePoolData();
        updateTokenBalance();
      }, interval);
      return () => clearInterval(intervalId);
    }
  }, [
    zkAccount, isPending, isPendingIncoming, updatePoolData, updateTokenBalance,
    giftCardTxHash, history, pendingDirectDeposits,
  ]);

  useEffect(() => {
    loadRelayerVersion();
    const interval = 3600 * 1000; // 1 hour
    const intervalId = setInterval(loadRelayerVersion, interval);
    return () => clearInterval(intervalId);
  }, [loadRelayerVersion]);

  useEffect(() => {
    const {seed, hasPassword} = getSeed();
    if (seed && hasPassword && !zkAccount) {
      openPasswordModal();
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    const {seed, hasPassword} = getSeed();
    if (seed && !hasPassword && !zkAccount) {
      if (zkClient) {
        loadZkAccount(seed);
      } else {
        setIsLoadingZkAccount(true);
      }
    }
  }, [loadZkAccount, zkClient, zkAccount]);

  useEffect(() => {
    if (isDemo) {
      const params = new URLSearchParams(window.location.search);
      const privateKey = params.get('code');
      const birthIndex = Number(params.get('index'));
      loadZkAccount(privateKey, birthIndex);
    }
  }, [isDemo, loadZkAccount]);

  return (
    <ZkAccountContext.Provider
      value={{
        zkAccount, balance, balances, zkClients, saveZkAccountMnemonic, deposit, isPoolSwitching, getSeed,
        withdraw, transfer, generateAddress, history, histories, unlockAccount, transferMulti,
        isLoadingZkAccount, isLoadingState, isLoadingHistory, isPending, pendingActions,
        removeZkAccountMnemonic, updatePoolData, minTxAmount, loadingPercentage,
        estimateFee, isLoadingLimits, limits, calcMaxTransferable,
        setPassword, verifyPassword, removePassword, pendingDirectDeposits,
        verifyShieldedAddress, verifyShieldedAddressWithPoolInfo, decryptMnemonic, relayerVersion, isDemo, updateLimits, lockAccount,
        switchToPool, giftCard, initializeGiftCard, deleteGiftCard, redeemGiftCard, isPendingIncoming,
      }}
    >
      {children}
    </ZkAccountContext.Provider>
  );
};
