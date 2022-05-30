const fs = require('fs');
const path = require('path');

require('@nomiclabs/hardhat-truffle5');
require('@nomiclabs/hardhat-solhint');
require('solidity-coverage');
require('hardhat-gas-reporter');
require('dotenv').config();
require('hardhat-deploy');

for (const f of fs.readdirSync(path.join(__dirname, 'hardhat'))) {
  require(path.join(__dirname, 'hardhat', f));
}

const enableGasReport = !!process.env.ENABLE_GAS_REPORT;

/**
 * @type import('hardhat/config').HardhatUserConfig
 */
require('@nomiclabs/hardhat-ethers');
//require("hardhat-deploy-ethers");

const ALCHEMY_API_KEY = "qApy2cT24XLsF9pnYopny_xp2IMWchHh";
const ALCHEMY_tatumRopsten_API_KEY = "favr7mQYa5P6DsUXJBX5Hb8h4mE0kdTZ";

const ROPSTEN_PRIVATE_KEY = "54a7c749c89600689271102f34334062022b951b7b34b63c88d2cb05c37712aa";


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
      url: `https://eth-ropsten.alchemyapi.io/v2/${ALCHEMY_tatumRopsten_API_KEY}`,
      accounts: [`${ROPSTEN_PRIVATE_KEY}`],
      gasPrice: `auto`
    },
    goerli: {
      url: `https://eth-ropsten.alchemyapi.io/v2/${ALCHEMY_API_KEY}`,
      accounts: [`${ROPSTEN_PRIVATE_KEY}`],
      gasPrice: 600000000000
    },
    alfajores: {
      url: "https://alfajores-forno.celo-testnet.org",
      // accounts: {
      //   mnemonic: "doll soul reason shoulder debris club reason plate galaxy secret dutch lonely",
      //   path: "m/44'/52752'/0'/0"
      // },
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
  gasReporter: {
    enable: enableGasReport,
    currency: 'USD',
    outputFile: process.env.CI ? 'gas-report.txt' : undefined,
  },
  mocha: {
    grep: 'Marketplace|NftAuction'
  }
};
