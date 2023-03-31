// async function main() {
//   // We get the contract to deploy
//   const Tatum721General = await ethers.getContractFactory("Tatum721General");
//   console.log("Deploying Tatum721General...");
//   const nft = await Tatum721General.deploy("MzNFT","MZT",true, {gasPrice: 600000000000}); // 2gwei);
//   await nft.deployed();
//   console.log("Tatum721General deployed to:", nft.address);
// }

// main()
//   .then(() => process.exit(0))
//   .catch(error => {
//     console.error(error);
//     process.exit(1);
//   });

module.exports = async ({getNamedAccounts, deployments}) => {
  const {deploy} = deployments;
  const {deployer} = await getNamedAccounts();
  await deploy('EadonForestClub', {
    from: deployer,
    args: ["EadonForestClub","Eadon",false],
    log: true,
  });
};
module.exports.tags = ['EadonForestClub'];