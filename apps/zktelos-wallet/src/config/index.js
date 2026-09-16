const isElectron = () => process.env.REACT_APP_BUILD_TARGET === 'electron';

const getAppBaseURL = () => {
  const href =
    (typeof window !== 'undefined' && window.location?.href) ||
    '';

  if (!href) return './';

  return href.replace(/\/[^/]*$/, '/') + '';
};

const assetURL = (relPath) => {
  const base = getAppBaseURL();
  return new URL(relPath, base).toString();
};

const config = {
  prod: {
    defaultPool: 'tlos_native',
    pools: {
      'tlos_native': {
        chainId: 40,
        poolAddress: '0xB5340818eE78D6221f631495346E2e55DA5BcA58',
        tokenAddress: '0xD102cE6A4dB07D247fcc28F366A623Df0938CA9E',
        relayerUrls: ['https://dsw2020napxes.cloudfront.net/'],
        delegatedProverUrls: [],
        coldStorageConfigPath: '',
        tokenSymbol: 'TLOS',
        tokenDecimals: 18,
        feeDecimals: 2,
        depositScheme: 'approve',
        addressPrefix: '',
        parameters: 'prod',
        isNative: true,
        minTxAmount: '5000000000', // 5 TLOS in shielded amount
        depositFeeBps: 20,
      },
      'tlos_usdce': {
        chainId: 40,
        poolAddress: '0xe47A4F0099cA16d61C678Dc75911F91e11deDAa3',
        tokenAddress: '0xF1815bd50389c46847f0Bda824eC8da914045D14',
        relayerUrls: ['https://d39zrx7k37xhn.cloudfront.net/'],
        delegatedProverUrls: [],
        coldStorageConfigPath: '',
        tokenSymbol: 'USDC.e',
        tokenDecimals: 6,
        feeDecimals: 2,
        depositScheme: 'approve',
        addressPrefix: '',
        parameters: 'prod',
        minTxAmount: '200000' // 0.2 USDC in shielded amount
      }
    },
    chains: {
      '40': {
        rpcUrls: ['https://rpc.telos.net']
      },
    },
    "snarkParamsSet": {
      "prod": isElectron() ? {
        transferParamsUrl: assetURL('assets/transfer_params_prod.bin'),
        transferVkUrl: assetURL('assets/transfer_verification_key_prod.json'),
      } : {
        transferParamsUrl: 'https://telos-privacy-params-prod.s3.us-east-2.amazonaws.com/transfer_params.bin',
        transferVkUrl: 'https://telos-privacy-params-prod.s3.us-east-2.amazonaws.com/transfer_verification_key.json',
      }
    }
  },
  dev: {
    defaultPool: 'tlos_testnet_native',
    pools: {
      'tlos_testnet_pusd': {
        chainId: 41,
        poolAddress: '0x88BFa2463b43c3F25524aA16C1843fb3C18f25a3',
        tokenAddress: '0x28d1BCc58E6Cd0270F45b63e4FFd13b3fF5E98af',
        relayerUrls: ['https://dj52jwsv8mae.cloudfront.net/'],
        delegatedProverUrls: [],
        coldStorageConfigPath: '',
        tokenSymbol: 'PUSD',
        tokenDecimals: 18,
        feeDecimals: 2,
        depositScheme: 'approve',
        addressPrefix: '',
        parameters: 'staging'
      },
      'tlos_testnet_native': {
        chainId: 41,
        poolAddress: '0x468585bfAeb2D2d84DD5b27750dD55CF65F3347f',
        tokenAddress: '0xaE85Bf723A9e74d6c663dd226996AC1b8d075AA9',
        relayerUrls: ['https://d3fpdfo0byy8s8.cloudfront.net/'],
        delegatedProverUrls: [],
        coldStorageConfigPath: '',
        tokenSymbol: 'TLOS',
        tokenDecimals: 18,
        feeDecimals: 2,
        depositScheme: 'approve',
        addressPrefix: '',
        parameters: 'staging',
        isNative: true,
        depositFeeBps: 20,
      }
    },
    "snarkParamsSet": {
      "staging": isElectron() ? {
        transferParamsUrl: assetURL('assets/transfer_params.bin'),
        transferVkUrl: assetURL('assets/transfer_verification_key.json'),
      } : {
        transferParamsUrl: 'https://telos-privacy-params.s3.us-east-2.amazonaws.com/transfer_params.bin',
        transferVkUrl: 'https://telos-privacy-params.s3.us-east-2.amazonaws.com/transfer_verification_key.json',
      }
    },
    chains: {
      '41': {
        rpcUrls: ['https://rpc.testnet.telos.net']
      },
    },
    extraPrefixes: [],
  }
};

export default config[process.env.REACT_APP_CONFIG || 'dev'];
