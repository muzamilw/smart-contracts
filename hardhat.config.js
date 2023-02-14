const fs = require('fs');
const path = require('path');

require('@nomiclabs/hardhat-truffle5');
require('@nomiclabs/hardhat-solhint');
require('solidity-coverage');
require('hardhat-gas-reporter');
require('dotenv').config();
require('hardhat-deploy');
require("@nomiclabs/hardhat-etherscan");

for (const f of fs.readdirSync(path.join(__dirname, 'hardhat'))) {
  require(path.join(__dirname, 'hardhat', f));
}

const enableGasReport = !!process.env.ENABLE_GAS_REPORT;

/**
 * @type import('hardhat/config').HardhatUserConfig
 */
require('@nomiclabs/hardhat-ethers');
//require("hardhat-deploy-ethers");in


module.exports = {
  solidity: {
    compilers: [
      {
        version: '0.6.12',
        settings: {
          optimizer: {
            enabled: true,
            runs: 200,
          },
        }
      },
      {
        version: '0.5.5',
        settings: {
          optimizer: {
            enabled: true,
            runs: 200,
          },
        }
      },
      {
        version: '0.8.7',
        settings: {
          optimizer: {
            enabled: true,
            runs: 200,
          },
        },
      },
    ]
  },
  defaultNetwork: "alfajores",
    namedAccounts: {
      deployer: 0
 },
  networks: {
    hardhat: {
      blockGasLimit: 10000000,
    },
    ropsten: {
      url: `https://eth-ropsten.alchemyapi.io/v2/${process.env.ALCHEMY_tatumRopsten_API_KEY}`,
      accounts: [process.env.PKEY],
      gasPrice: `auto`
    },
    goerli: {
      url: `https://eth-ropsten.alchemyapi.io/v2/${process.env.ALCHEMY_API_KEY}`,
      accounts: [process.env.PKEY],
      gasPrice: 600000000000
    },
    alfajores: {
      url: "https://alfajores-forno.celo-testnet.org",
     
      accounts: [process.env.PKEY],

      chainId: 44787,
      gasPrice: 600000000000
    },
    celo: {
      url: "https://forno.celo.org",
      accounts: {
        mnemonic: process.env.MNEMONIC,
        path: "m/44'/52752'/0'/0"
      },
      chainId: 42220
    },
    bsctest: {
      url: "https://data-seed-prebsc-1-s1.binance.org:8545/",
      chainId: 97,
      accounts: ['cd2fe348ecbde2a9b1caf0429dfaac4b656b9d969eca290cc106e6cbb38ef1e9'],
      gasPrice: 30 * 1e9
    },
  },
  etherscan : {
    apiKey: {
      celo: process.env.etherscanapike,
      goerli: "<goerli-api-key>",
      alfajores: process.env.etherscanapike,
    },
    customChains: [
      {
        network: 'celo',
        chainId: 42220,
        urls: {
          apiURL: 'https://explorer.celo.org/api',
          browserURL: 'https://explorer.celo.org/',
        },
      },
      {
        network: 'alfajores',
        chainId: 44787,
        urls: {
          apiURL: 'https://api-alfajores.celoscan.io/api',
          browserURL: 'https://api-alfajores.celoscan.io/api',
        },
      },
    ],
  },
  gasReporter: {
    enable: enableGasReport,
    currency: 'USD',
    outputFile: process.env.CI ? 'gas-report.txt' : undefined,
  },
  mocha: {
    grep: 'Marketplace|NftAuction'
  }
};
