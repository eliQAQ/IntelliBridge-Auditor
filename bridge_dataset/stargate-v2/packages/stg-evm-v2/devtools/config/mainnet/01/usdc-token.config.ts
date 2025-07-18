import assert from 'assert'

import { TokenName } from '@stargatefinance/stg-definitions-v2'
import { USDCNodeConfig } from '@stargatefinance/stg-devtools-v2'

import { OmniGraphHardhat, createContractFactory, createGetHreByEid } from '@layerzerolabs/devtools-evm-hardhat'
import { EndpointId } from '@layerzerolabs/lz-definitions'

import { getUSDCProxyDeployName } from '../../../../ops/util'
import { createGetAssetAddresses, getAssetNetworkConfig } from '../../../../ts-src/utils/util'
import { getSafeAddress } from '../../utils'
import {
    onAbstract,
    onApe,
    onBera,
    onBotanix,
    onCodex,
    onCronosevm,
    onDegen,
    onFlare,
    onFlow,
    onFuse,
    onGlue,
    onGoat,
    onGravity,
    onHemi,
    onInk,
    onIota,
    onIslander,
    onKlaytn,
    onLightlink,
    onNibiru,
    onPeaq,
    onPlume,
    onPlumephoenix,
    onRarible,
    onRootstock,
    onStory,
    onSuperposition,
    onTaiko,
    onTelos,
    onXchain,
    onXdc,
} from '../utils'

const proxyContract = { contractName: getUSDCProxyDeployName() }
const fiatContract = { contractName: 'FiatTokenV2_2' }

// Except for chains where it's deployed externally
const usdcPeaqAsset = getAssetNetworkConfig(EndpointId.PEAQ_V2_MAINNET, TokenName.USDC)
assert(usdcPeaqAsset.address != null, `External USDC address not found for PEAQ`)

const usdcAbstractAsset = getAssetNetworkConfig(EndpointId.ABSTRACT_V2_MAINNET, TokenName.USDC)
assert(usdcAbstractAsset.address != null, `External USDC address not found for ABSTRACT`)

const usdcApeAsset = getAssetNetworkConfig(EndpointId.APE_V2_MAINNET, TokenName.USDC)
assert(usdcApeAsset.address != null, `External USDC address not found for APE`)

const usdcBeraAsset = getAssetNetworkConfig(EndpointId.BERA_V2_MAINNET, TokenName.USDC)
assert(usdcBeraAsset.address != null, `External USDC address not found for BERA`)

const usdcBotanixAsset = getAssetNetworkConfig(EndpointId.BOTANIX_V2_MAINNET, TokenName.USDC)
assert(usdcBotanixAsset.address != null, `External USDC address not found for BOTANIX`)

const usdcCodexAsset = getAssetNetworkConfig(EndpointId.CODEX_V2_MAINNET, TokenName.USDC)
assert(usdcCodexAsset.address != null, `External USDC address not found for CODEX`)

const usdcCronosevmAsset = getAssetNetworkConfig(EndpointId.CRONOSEVM_V2_MAINNET, TokenName.USDC)
assert(usdcCronosevmAsset.address != null, `External USDC address not found for CRONOS EVM`)

const usdcDegenAsset = getAssetNetworkConfig(EndpointId.DEGEN_V2_MAINNET, TokenName.USDC)
assert(usdcDegenAsset.address != null, `External USDC address not found for DEGEN`)

const usdcFlowAsset = getAssetNetworkConfig(EndpointId.FLOW_V2_MAINNET, TokenName.USDC)
assert(usdcFlowAsset.address != null, `External USDC address not found for FLOW`)

const usdcFuseAsset = getAssetNetworkConfig(EndpointId.FUSE_V2_MAINNET, TokenName.USDC)
assert(usdcFuseAsset.address != null, `External USDC address not found for FUSE`)

const usdcGlueAsset = getAssetNetworkConfig(EndpointId.GLUE_V2_MAINNET, TokenName.USDC)
assert(usdcGlueAsset.address != null, `External USDC address not found for GLUE`)

const usdcGoatAsset = getAssetNetworkConfig(EndpointId.GOAT_V2_MAINNET, TokenName.USDC)
assert(usdcGoatAsset.address != null, 'External USDC address not found for GLUE')

const usdcHemiAsset = getAssetNetworkConfig(EndpointId.HEMI_V2_MAINNET, TokenName.USDC)
assert(usdcHemiAsset.address != null, `External USDC address not found for HEMI`)

const usdcInkAsset = getAssetNetworkConfig(EndpointId.INK_V2_MAINNET, TokenName.USDC)
assert(usdcInkAsset.address != null, `External USDC address not found for INK`)

const usdcIslanderAsset = getAssetNetworkConfig(EndpointId.ISLANDER_V2_MAINNET, TokenName.USDC)
assert(usdcIslanderAsset.address != null, `External USDC address not found for ISLANDER`)

const usdcNibiruAsset = getAssetNetworkConfig(EndpointId.NIBIRU_V2_MAINNET, TokenName.USDC)
assert(usdcNibiruAsset.address != null, `External USDC address not found for NIBIRU`)

const usdcPlumeAsset = getAssetNetworkConfig(EndpointId.PLUME_V2_MAINNET, TokenName.USDC)
assert(usdcPlumeAsset.address != null, `External USDC address not found for PLUME`)

const usdcPlumephoenixAsset = getAssetNetworkConfig(EndpointId.PLUMEPHOENIX_V2_MAINNET, TokenName.USDC)
assert(usdcPlumephoenixAsset.address != null, `External USDC address not found for PLUMEPHOENIX`)

const usdcRootstockAsset = getAssetNetworkConfig(EndpointId.ROOTSTOCK_V2_MAINNET, TokenName.USDC)
assert(usdcRootstockAsset.address != null, `External USDC address not found for ROOTSTOCK`)

const usdcStoryAsset = getAssetNetworkConfig(EndpointId.STORY_V2_MAINNET, TokenName.USDC)
assert(usdcStoryAsset.address != null, `External USDC address not found for STORY`)

const usdcSuperpositionAsset = getAssetNetworkConfig(EndpointId.SUPERPOSITION_V2_MAINNET, TokenName.USDC)
assert(usdcSuperpositionAsset.address != null, `External USDC address not found for SUPERPOSITION`)

const usdcTelosAsset = getAssetNetworkConfig(EndpointId.TELOS_V2_MAINNET, TokenName.USDC)
assert(usdcTelosAsset.address != null, `External USDC address not found for TELOS`)

const usdcXdcAsset = getAssetNetworkConfig(EndpointId.XDC_V2_MAINNET, TokenName.USDC)
assert(usdcXdcAsset.address != null, `External USDC address not found for XDC`)

export default async (): Promise<OmniGraphHardhat<USDCNodeConfig, unknown>> => {
    // First let's create the HardhatRuntimeEnvironment objects for all networks
    const getEnvironment = createGetHreByEid()
    const contractFactory = createContractFactory(getEnvironment)

    // The newer USDC deployments (since December 2024)

    const abstractUSDCProxy = await contractFactory(
        onAbstract({ contractName: 'FiatTokenProxy', address: usdcAbstractAsset.address })
    )
    const apeUSDCProxy = await contractFactory(onApe({ contractName: 'FiatTokenProxy', address: usdcApeAsset.address }))
    const beraUSDCProxy = await contractFactory(
        onBera({ contractName: 'FiatTokenProxy', address: usdcBeraAsset.address })
    )
    const botanixUSDCProxy = await contractFactory(
        onBotanix({ contractName: 'FiatTokenProxy', address: usdcBotanixAsset.address })
    )
    const codexUSDCProxy = await contractFactory(
        onCodex({ contractName: 'FiatTokenProxy', address: usdcCodexAsset.address })
    )
    const cronosevmUSDCProxy = await contractFactory(
        onCronosevm({ contractName: 'FiatTokenProxy', address: usdcCronosevmAsset.address })
    )
    const degenUSDCProxy = await contractFactory(
        onDegen({ contractName: 'FiatTokenProxy', address: usdcDegenAsset.address })
    )
    const flareUSDCProxy = await contractFactory(onFlare(proxyContract))
    const flowUSDCProxy = await contractFactory(
        onFlow({ contractName: 'FiatTokenProxy', address: usdcFlowAsset.address })
    )
    const fuseUSDCProxy = await contractFactory(
        onFuse({ contractName: 'FiatTokenProxy', address: usdcFuseAsset.address })
    )
    const glueUSDCProxy = await contractFactory(
        onGlue({ contractName: 'FiatTokenProxy', address: usdcGlueAsset.address })
    )
    const goatUSDCProxy = await contractFactory(
        onGoat({ contractName: 'FiatTokenProxy', address: usdcGoatAsset.address })
    )
    const gravityUSDCProxy = await contractFactory(onGravity(proxyContract))
    const hemiUSDCProxy = await contractFactory(
        onHemi({ contractName: 'FiatTokenProxy', address: usdcHemiAsset.address })
    )
    const inkUSDCProxy = await contractFactory(onInk({ contractName: 'FiatTokenProxy', address: usdcInkAsset.address }))
    const iotaUSDCProxy = await contractFactory(onIota(proxyContract))
    const islanderUSDCProxy = await contractFactory(
        onIslander({ contractName: 'FiatTokenProxy', address: usdcIslanderAsset.address })
    )
    const klaytnUSDCProxy = await contractFactory(onKlaytn(proxyContract))
    const lightlinkUSDCProxy = await contractFactory(onLightlink(proxyContract))
    const nibiruUSDCProxy = await contractFactory(
        onNibiru({ contractName: 'FiatTokenProxy', address: usdcNibiruAsset.address })
    )
    const peaqUSDCProxy = await contractFactory(
        onPeaq({ contractName: 'FiatTokenProxy', address: usdcPeaqAsset.address })
    )
    const plumeUSDCProxy = await contractFactory(
        onPlume({ contractName: 'FiatTokenProxy', address: usdcPlumeAsset.address })
    )
    const plumephoenixUSDCProxy = await contractFactory(
        onPlumephoenix({ contractName: 'FiatTokenProxy', address: usdcPlumephoenixAsset.address })
    )

    const raribleUSDCProxy = await contractFactory(onRarible(proxyContract))
    const rootstockUSDCProxy = await contractFactory(
        onRootstock({ contractName: 'FiatTokenProxy', address: usdcRootstockAsset.address })
    )
    const storyUSDCProxy = await contractFactory(
        onStory({ contractName: 'FiatTokenProxy', address: usdcStoryAsset.address })
    )
    const superpositionUSDCProxy = await contractFactory(
        onSuperposition({ contractName: 'FiatTokenProxy', address: usdcSuperpositionAsset.address })
    )
    const taikoUSDCProxy = await contractFactory(onTaiko(proxyContract))
    const telosUSDCProxy = await contractFactory(
        onTelos({ contractName: 'FiatTokenProxy', address: usdcTelosAsset.address })
    )
    const xchainUSDCProxy = await contractFactory(onXchain(proxyContract))
    const xdcUSDCProxy = await contractFactory({
        contractName: 'FiatTokenProxy',
        address: usdcXdcAsset.address,
        eid: EndpointId.XDC_V2_MAINNET,
    })

    // Get the corresponding underlying USDC contract
    const abstractUSDC = onAbstract({ ...fiatContract, address: abstractUSDCProxy.contract.address })
    const abstractStargateMultisig = getSafeAddress(EndpointId.ABSTRACT_V2_MAINNET)

    const apeUSDC = onApe({ ...fiatContract, address: apeUSDCProxy.contract.address })
    const apeStargateMultisig = getSafeAddress(EndpointId.APE_V2_MAINNET)

    const beraUSDC = onBera({ ...fiatContract, address: beraUSDCProxy.contract.address })
    const beraStargateMultisig = getSafeAddress(EndpointId.BERA_V2_MAINNET)

    const botanixUSDC = onBotanix({ ...fiatContract, address: botanixUSDCProxy.contract.address })
    const botanixStargateMultisig = getSafeAddress(EndpointId.BOTANIX_V2_MAINNET)

    const codexUSDC = onCodex({ ...fiatContract, address: codexUSDCProxy.contract.address })
    const codexStargateMultisig = getSafeAddress(EndpointId.CODEX_V2_MAINNET)

    const cronosevmUSDC = onCronosevm({ ...fiatContract, address: cronosevmUSDCProxy.contract.address })
    const cronosevmStargateMultisig = getSafeAddress(EndpointId.CRONOSEVM_V2_MAINNET)

    const degenUSDC = onDegen({ ...fiatContract, address: degenUSDCProxy.contract.address })
    const degenStargateMultisig = getSafeAddress(EndpointId.DEGEN_V2_MAINNET)

    const flareUSDC = onFlare({ ...fiatContract, address: flareUSDCProxy.contract.address })
    const flareStargateMultisig = getSafeAddress(EndpointId.FLARE_V2_MAINNET)

    const flowUSDC = onFlow({ ...fiatContract, address: flowUSDCProxy.contract.address })
    const flowStargateMultisig = getSafeAddress(EndpointId.FLOW_V2_MAINNET)

    const fuseUSDC = onFuse({ ...fiatContract, address: fuseUSDCProxy.contract.address })
    const fuseStargateMultisig = getSafeAddress(EndpointId.FUSE_V2_MAINNET)

    const glueUSDC = onGlue({ ...fiatContract, address: glueUSDCProxy.contract.address })
    const glueStargateMultisig = getSafeAddress(EndpointId.GLUE_V2_MAINNET)

    const goatUSDC = onGoat({ ...fiatContract, address: goatUSDCProxy.contract.address })
    const goatStargateMultisig = getSafeAddress(EndpointId.GOAT_V2_MAINNET)

    const gravityUSDC = onGravity({ ...fiatContract, address: gravityUSDCProxy.contract.address })
    const gravityStargateMultisig = getSafeAddress(EndpointId.GRAVITY_V2_MAINNET)

    const hemiUSDC = onHemi({ ...fiatContract, address: hemiUSDCProxy.contract.address })
    const hemiStargateMultisig = getSafeAddress(EndpointId.HEMI_V2_MAINNET)

    const inkUSDC = onInk({ ...fiatContract, address: inkUSDCProxy.contract.address })
    const inkStargateMultisig = getSafeAddress(EndpointId.INK_V2_MAINNET)

    const iotaUSDC = onIota({ ...fiatContract, address: iotaUSDCProxy.contract.address })
    const iotaStargateMultisig = getSafeAddress(EndpointId.IOTA_V2_MAINNET)

    const islanderUSDC = onIslander({ ...fiatContract, address: islanderUSDCProxy.contract.address })
    const islanderStargateMultisig = getSafeAddress(EndpointId.ISLANDER_V2_MAINNET)

    const klaytnUSDC = onKlaytn({ ...fiatContract, address: klaytnUSDCProxy.contract.address })
    const klaytnStargateMultisig = getSafeAddress(EndpointId.KLAYTN_V2_MAINNET)

    const lightlinkUSDC = onLightlink({ ...fiatContract, address: lightlinkUSDCProxy.contract.address })
    const lightlinkStargateMultisig = getSafeAddress(EndpointId.LIGHTLINK_V2_MAINNET)

    const nibiruUSDC = onNibiru({ ...fiatContract, address: nibiruUSDCProxy.contract.address })
    const nibiruStargateMultisig = getSafeAddress(EndpointId.NIBIRU_V2_MAINNET)

    const peaqUSDC = onPeaq({ ...fiatContract, address: peaqUSDCProxy.contract.address })
    const peaqStargateMultisig = getSafeAddress(EndpointId.PEAQ_V2_MAINNET)

    const plumeUSDC = onPlume({ ...fiatContract, address: plumeUSDCProxy.contract.address })
    const plumeStargateMultisig = getSafeAddress(EndpointId.PLUME_V2_MAINNET)

    const plumephoenixUSDC = onPlumephoenix({ ...fiatContract, address: plumephoenixUSDCProxy.contract.address })
    const plumephoenixStargateMultisig = getSafeAddress(EndpointId.PLUMEPHOENIX_V2_MAINNET)

    const raribleUSDC = onRarible({ ...fiatContract, address: raribleUSDCProxy.contract.address })
    const raribleStargateMultisig = getSafeAddress(EndpointId.RARIBLE_V2_MAINNET)

    const rootstockUSDC = onRootstock({ ...fiatContract, address: rootstockUSDCProxy.contract.address })
    const rootstockStargateMultisig = getSafeAddress(EndpointId.ROOTSTOCK_V2_MAINNET)

    const storyUSDC = onStory({ ...fiatContract, address: storyUSDCProxy.contract.address })
    const storyStargateMultisig = getSafeAddress(EndpointId.STORY_V2_MAINNET)

    const superpositionUSDC = onSuperposition({ ...fiatContract, address: superpositionUSDCProxy.contract.address })
    const superpositionStargateMultisig = getSafeAddress(EndpointId.SUPERPOSITION_V2_MAINNET)

    const taikoUSDC = onTaiko({ ...fiatContract, address: taikoUSDCProxy.contract.address })
    const taikoStargateMultisig = getSafeAddress(EndpointId.TAIKO_V2_MAINNET)

    const telosUSDC = onTelos({ ...fiatContract, address: telosUSDCProxy.contract.address })
    const telosStargateMultisig = getSafeAddress(EndpointId.TELOS_V2_MAINNET)

    const xchainUSDC = onXchain({ ...fiatContract, address: xchainUSDCProxy.contract.address })
    const xchainStargateMultisig = getSafeAddress(EndpointId.XCHAIN_V2_MAINNET)

    const xdcUSDC = onXdc({ ...fiatContract, address: xdcUSDCProxy.contract.address })
    const xdcStargateMultisig = getSafeAddress(EndpointId.XDC_V2_MAINNET)

    // Now we collect the address of the deployed assets(StargateOft.sol etc.)
    const usdcAssets = [TokenName.USDC] as const
    const getAssetAddresses = createGetAssetAddresses(getEnvironment)
    const abstractAssetAddresses = await getAssetAddresses(EndpointId.ABSTRACT_V2_MAINNET, usdcAssets)
    const apeAssetAddresses = await getAssetAddresses(EndpointId.APE_V2_MAINNET, usdcAssets)
    const beraAssetAddresses = await getAssetAddresses(EndpointId.BERA_V2_MAINNET, usdcAssets)
    const botanixAssetAddresses = await getAssetAddresses(EndpointId.BOTANIX_V2_MAINNET, usdcAssets)
    const codexAssetAddresses = await getAssetAddresses(EndpointId.CODEX_V2_MAINNET, usdcAssets)
    const cronosevmAssetAddresses = await getAssetAddresses(EndpointId.CRONOSEVM_V2_MAINNET, usdcAssets)
    const degenAssetAddresses = await getAssetAddresses(EndpointId.DEGEN_V2_MAINNET, usdcAssets)
    const flareAssetAddresses = await getAssetAddresses(EndpointId.FLARE_V2_MAINNET, usdcAssets)
    const flowAssetAddresses = await getAssetAddresses(EndpointId.FLOW_V2_MAINNET, usdcAssets)
    const fuseAssetAddresses = await getAssetAddresses(EndpointId.FUSE_V2_MAINNET, usdcAssets)
    const glueAssetAddresses = await getAssetAddresses(EndpointId.GLUE_V2_MAINNET, usdcAssets)
    const goatAssetAddresses = await getAssetAddresses(EndpointId.GOAT_V2_MAINNET, usdcAssets)
    const gravityAssetAddresses = await getAssetAddresses(EndpointId.GRAVITY_V2_MAINNET, usdcAssets)
    const hemiAssetAddresses = await getAssetAddresses(EndpointId.HEMI_V2_MAINNET, usdcAssets)
    const inkAssetAddresses = await getAssetAddresses(EndpointId.INK_V2_MAINNET, usdcAssets)
    const iotaAssetAddresses = await getAssetAddresses(EndpointId.IOTA_V2_MAINNET, usdcAssets)
    const islanderAssetAddresses = await getAssetAddresses(EndpointId.ISLANDER_V2_MAINNET, usdcAssets)
    const klaytnAssetAddresses = await getAssetAddresses(EndpointId.KLAYTN_V2_MAINNET, usdcAssets)
    const lightlinkAssetAddresses = await getAssetAddresses(EndpointId.LIGHTLINK_V2_MAINNET, usdcAssets)
    const nibiruAssetAddresses = await getAssetAddresses(EndpointId.NIBIRU_V2_MAINNET, usdcAssets)
    const peaqAssetAddresses = await getAssetAddresses(EndpointId.PEAQ_V2_MAINNET, usdcAssets)
    const plumeAssetAddresses = await getAssetAddresses(EndpointId.PLUME_V2_MAINNET, usdcAssets)
    const plumephoenixAssetAddresses = await getAssetAddresses(EndpointId.PLUMEPHOENIX_V2_MAINNET, usdcAssets)
    const raribleAssetAddresses = await getAssetAddresses(EndpointId.RARIBLE_V2_MAINNET, usdcAssets)
    const rootstockAssetAddresses = await getAssetAddresses(EndpointId.ROOTSTOCK_V2_MAINNET, usdcAssets)
    const storyAssetAddresses = await getAssetAddresses(EndpointId.STORY_V2_MAINNET, usdcAssets)
    const superpositionAssetAddresses = await getAssetAddresses(EndpointId.SUPERPOSITION_V2_MAINNET, usdcAssets)
    const taikoAssetAddresses = await getAssetAddresses(EndpointId.TAIKO_V2_MAINNET, usdcAssets)
    const telosAssetAddresses = await getAssetAddresses(EndpointId.TELOS_V2_MAINNET, usdcAssets)
    const xchainAssetAddresses = await getAssetAddresses(EndpointId.XCHAIN_V2_MAINNET, usdcAssets)
    const xdcAssetAddresses = await getAssetAddresses(EndpointId.XDC_V2_MAINNET, usdcAssets)

    return {
        contracts: [
            {
                contract: abstractUSDC,
                config: {
                    owner: abstractStargateMultisig,
                    masterMinter: abstractStargateMultisig,
                    pauser: abstractStargateMultisig,
                    rescuer: abstractStargateMultisig,
                    blacklister: abstractStargateMultisig,
                    minters: {
                        [abstractAssetAddresses.USDC]: 2n ** 256n - 1n,
                    },
                },
            },
            {
                contract: apeUSDC,
                config: {
                    owner: apeStargateMultisig,
                    masterMinter: apeStargateMultisig,
                    pauser: apeStargateMultisig,
                    rescuer: apeStargateMultisig,
                    blacklister: apeStargateMultisig,
                    minters: {
                        [apeAssetAddresses.USDC]: 2n ** 256n - 1n,
                    },
                },
            },
            {
                contract: beraUSDC,
                config: {
                    owner: beraStargateMultisig,
                    masterMinter: beraStargateMultisig,
                    pauser: beraStargateMultisig,
                    rescuer: beraStargateMultisig,
                    blacklister: beraStargateMultisig,
                    minters: {
                        [beraAssetAddresses.USDC]: 2n ** 256n - 1n,
                    },
                },
            },
            {
                contract: botanixUSDC,
                config: {
                    owner: botanixStargateMultisig,
                    masterMinter: botanixStargateMultisig,
                    pauser: botanixStargateMultisig,
                    rescuer: botanixStargateMultisig,
                    blacklister: botanixStargateMultisig,
                    minters: {
                        [botanixAssetAddresses.USDC]: 2n ** 256n - 1n,
                    },
                },
            },
            {
                contract: codexUSDC,
                config: {
                    owner: codexStargateMultisig,
                    masterMinter: codexStargateMultisig,
                    pauser: codexStargateMultisig,
                    rescuer: codexStargateMultisig,
                    blacklister: codexStargateMultisig,
                    minters: {
                        [codexAssetAddresses.USDC]: 2n ** 256n - 1n,
                    },
                },
            },
            {
                contract: cronosevmUSDC,
                config: {
                    owner: cronosevmStargateMultisig,
                    masterMinter: cronosevmStargateMultisig,
                    pauser: cronosevmStargateMultisig,
                    rescuer: cronosevmStargateMultisig,
                    blacklister: cronosevmStargateMultisig,
                    minters: {
                        [cronosevmAssetAddresses.USDC]: 2n ** 256n - 1n,
                    },
                },
            },
            {
                contract: degenUSDC,
                config: {
                    owner: degenStargateMultisig,
                    masterMinter: degenStargateMultisig,
                    pauser: degenStargateMultisig,
                    rescuer: degenStargateMultisig,
                    blacklister: degenStargateMultisig,
                    minters: {
                        [degenAssetAddresses.USDC]: 2n ** 256n - 1n,
                    },
                },
            },
            {
                contract: flareUSDC,
                config: {
                    owner: flareStargateMultisig,
                    masterMinter: flareStargateMultisig,
                    pauser: flareStargateMultisig,
                    rescuer: flareStargateMultisig,
                    blacklister: flareStargateMultisig,
                    minters: {
                        [flareAssetAddresses.USDC]: 2n ** 256n - 1n,
                    },
                },
            },
            {
                contract: flowUSDC,
                config: {
                    owner: flowStargateMultisig,
                    masterMinter: flowStargateMultisig,
                    pauser: flowStargateMultisig,
                    rescuer: flowStargateMultisig,
                    blacklister: flowStargateMultisig,
                    minters: {
                        [flowAssetAddresses.USDC]: 2n ** 256n - 1n,
                    },
                },
            },
            {
                contract: fuseUSDC,
                config: {
                    owner: fuseStargateMultisig,
                    masterMinter: fuseStargateMultisig,
                    pauser: fuseStargateMultisig,
                    rescuer: fuseStargateMultisig,
                    blacklister: fuseStargateMultisig,
                    minters: {
                        [fuseAssetAddresses.USDC]: 2n ** 256n - 1n,
                    },
                },
            },
            {
                contract: glueUSDC,
                config: {
                    owner: glueStargateMultisig,
                    masterMinter: glueStargateMultisig,
                    pauser: glueStargateMultisig,
                    rescuer: glueStargateMultisig,
                    blacklister: glueStargateMultisig,
                    minters: {
                        [glueAssetAddresses.USDC]: 2n ** 256n - 1n,
                    },
                },
            },
            {
                contract: goatUSDC,
                config: {
                    owner: goatStargateMultisig,
                    masterMinter: goatStargateMultisig,
                    pauser: goatStargateMultisig,
                    rescuer: goatStargateMultisig,
                    blacklister: goatStargateMultisig,
                    minters: {
                        [goatAssetAddresses.USDC]: 2n ** 256n - 1n,
                    },
                },
            },
            {
                contract: gravityUSDC,
                config: {
                    owner: gravityStargateMultisig,
                    masterMinter: gravityStargateMultisig,
                    pauser: gravityStargateMultisig,
                    rescuer: gravityStargateMultisig,
                    blacklister: gravityStargateMultisig,
                    minters: {
                        [gravityAssetAddresses.USDC]: 2n ** 256n - 1n,
                    },
                },
            },
            {
                contract: hemiUSDC,
                config: {
                    owner: hemiStargateMultisig,
                    masterMinter: hemiStargateMultisig,
                    pauser: hemiStargateMultisig,
                    rescuer: hemiStargateMultisig,
                    blacklister: hemiStargateMultisig,
                    minters: {
                        [hemiAssetAddresses.USDC]: 2n ** 256n - 1n,
                    },
                },
            },
            {
                contract: inkUSDC,
                config: {
                    owner: inkStargateMultisig,
                    masterMinter: inkStargateMultisig,
                    pauser: inkStargateMultisig,
                    rescuer: inkStargateMultisig,
                    blacklister: inkStargateMultisig,
                    minters: {
                        [inkAssetAddresses.USDC]: 2n ** 256n - 1n,
                    },
                },
            },
            {
                contract: iotaUSDC,
                config: {
                    owner: iotaStargateMultisig,
                    masterMinter: iotaStargateMultisig,
                    pauser: iotaStargateMultisig,
                    rescuer: iotaStargateMultisig,
                    blacklister: iotaStargateMultisig,
                    minters: {
                        [iotaAssetAddresses.USDC]: 2n ** 256n - 1n,
                    },
                },
            },
            {
                contract: islanderUSDC,
                config: {
                    owner: islanderStargateMultisig,
                    masterMinter: islanderStargateMultisig,
                    pauser: islanderStargateMultisig,
                    rescuer: islanderStargateMultisig,
                    blacklister: islanderStargateMultisig,
                    minters: {
                        [islanderAssetAddresses.USDC]: 2n ** 256n - 1n,
                    },
                },
            },
            {
                contract: klaytnUSDC,
                config: {
                    owner: klaytnStargateMultisig,
                    masterMinter: klaytnStargateMultisig,
                    pauser: klaytnStargateMultisig,
                    rescuer: klaytnStargateMultisig,
                    blacklister: klaytnStargateMultisig,
                    minters: {
                        [klaytnAssetAddresses.USDC]: 2n ** 256n - 1n,
                    },
                },
            },
            {
                contract: lightlinkUSDC,
                config: {
                    owner: lightlinkStargateMultisig,
                    masterMinter: lightlinkStargateMultisig,
                    pauser: lightlinkStargateMultisig,
                    rescuer: lightlinkStargateMultisig,
                    blacklister: lightlinkStargateMultisig,
                    minters: {
                        [lightlinkAssetAddresses.USDC]: 2n ** 256n - 1n,
                    },
                },
            },
            {
                contract: nibiruUSDC,
                config: {
                    owner: nibiruStargateMultisig,
                    masterMinter: nibiruStargateMultisig,
                    pauser: nibiruStargateMultisig,
                    rescuer: nibiruStargateMultisig,
                    blacklister: nibiruStargateMultisig,
                    minters: {
                        [nibiruAssetAddresses.USDC]: 2n ** 256n - 1n,
                    },
                },
            },
            {
                contract: peaqUSDC,
                config: {
                    owner: peaqStargateMultisig,
                    masterMinter: peaqStargateMultisig,
                    pauser: peaqStargateMultisig,
                    rescuer: peaqStargateMultisig,
                    blacklister: peaqStargateMultisig,
                    minters: {
                        [peaqAssetAddresses.USDC]: 2n ** 256n - 1n,
                    },
                },
            },
            {
                contract: plumeUSDC,
                config: {
                    owner: plumeStargateMultisig,
                    masterMinter: plumeStargateMultisig,
                    pauser: plumeStargateMultisig,
                    rescuer: plumeStargateMultisig,
                    blacklister: plumeStargateMultisig,
                    minters: {
                        [plumeAssetAddresses.USDC]: 2n ** 256n - 1n,
                    },
                },
            },
            {
                contract: plumephoenixUSDC,
                config: {
                    owner: plumephoenixStargateMultisig,
                    masterMinter: plumephoenixStargateMultisig,
                    pauser: plumephoenixStargateMultisig,
                    rescuer: plumephoenixStargateMultisig,
                    blacklister: plumephoenixStargateMultisig,
                    minters: {
                        [plumephoenixAssetAddresses.USDC]: 2n ** 256n - 1n,
                    },
                },
            },
            {
                contract: raribleUSDC,
                config: {
                    owner: raribleStargateMultisig,
                    masterMinter: raribleStargateMultisig,
                    pauser: raribleStargateMultisig,
                    rescuer: raribleStargateMultisig,
                    blacklister: raribleStargateMultisig,
                    minters: {
                        [raribleAssetAddresses.USDC]: 2n ** 256n - 1n,
                    },
                },
            },
            {
                contract: rootstockUSDC,
                config: {
                    owner: rootstockStargateMultisig,
                    masterMinter: rootstockStargateMultisig,
                    pauser: rootstockStargateMultisig,
                    rescuer: rootstockStargateMultisig,
                    blacklister: rootstockStargateMultisig,
                    minters: {
                        [rootstockAssetAddresses.USDC]: 2n ** 256n - 1n,
                    },
                },
            },
            {
                contract: storyUSDC,
                config: {
                    owner: storyStargateMultisig,
                    masterMinter: storyStargateMultisig,
                    pauser: storyStargateMultisig,
                    rescuer: storyStargateMultisig,
                    blacklister: storyStargateMultisig,
                    minters: {
                        [storyAssetAddresses.USDC]: 2n ** 256n - 1n,
                    },
                },
            },
            {
                contract: superpositionUSDC,
                config: {
                    owner: superpositionStargateMultisig,
                    masterMinter: superpositionStargateMultisig,
                    pauser: superpositionStargateMultisig,
                    rescuer: superpositionStargateMultisig,
                    blacklister: superpositionStargateMultisig,
                    minters: {
                        [superpositionAssetAddresses.USDC]: 2n ** 256n - 1n,
                    },
                },
            },
            {
                contract: taikoUSDC,
                config: {
                    owner: taikoStargateMultisig,
                    masterMinter: taikoStargateMultisig,
                    pauser: taikoStargateMultisig,
                    rescuer: taikoStargateMultisig,
                    blacklister: taikoStargateMultisig,
                    minters: {
                        [taikoAssetAddresses.USDC]: 2n ** 256n - 1n,
                    },
                },
            },
            {
                contract: telosUSDC,
                config: {
                    owner: telosStargateMultisig,
                    masterMinter: telosStargateMultisig,
                    pauser: telosStargateMultisig,
                    rescuer: telosStargateMultisig,
                    blacklister: telosStargateMultisig,
                    minters: {
                        [telosAssetAddresses.USDC]: 2n ** 256n - 1n,
                    },
                },
            },
            {
                contract: xchainUSDC,
                config: {
                    owner: xchainStargateMultisig,
                    masterMinter: xchainStargateMultisig,
                    pauser: xchainStargateMultisig,
                    rescuer: xchainStargateMultisig,
                    blacklister: xchainStargateMultisig,
                    minters: {
                        [xchainAssetAddresses.USDC]: 2n ** 256n - 1n,
                    },
                },
            },
            {
                contract: xdcUSDC,
                config: {
                    owner: xdcStargateMultisig,
                    masterMinter: xdcStargateMultisig,
                    pauser: xdcStargateMultisig,
                    rescuer: xdcStargateMultisig,
                    blacklister: xdcStargateMultisig,
                    minters: {
                        [xdcAssetAddresses.USDC]: 2n ** 256n - 1n,
                    },
                },
            },
        ],
        connections: [],
    }
}
