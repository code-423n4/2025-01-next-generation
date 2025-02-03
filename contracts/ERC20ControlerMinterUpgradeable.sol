// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";

abstract contract ERC20ControlerMinterUpgradeable is ERC20Upgradeable, AccessControlEnumerableUpgradeable {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant MASTER_MINTER = keccak256("MASTER_MINTER");

//Maps the minter addr with The minting amount allowed for the minter
    mapping(address => uint256) public minterAllowed;

    bytes32 public constant CONTROLLER = keccak256("CONTROLLER");

    bool public _operating;
    address internal _operatingController;

    event MinterAllowanceUpdated(address indexed minter, uint256 minterAllowedAmount);
    event Mint(address indexed minter, address indexed to, uint256 amount);
    event Burn(address indexed minter, uint256 amount);
    event SwitchOperatingState(address indexed controler, bool state);

    error AlreadyMasterMinter(address account);
    error NotController(address account);
    error SafetySwitchOnUnauthorized(address account);
    error OperationsOff();
    error NotMinter(address account);
    error mintingAllowedAmountExceeded(uint256 amount, uint256 mintingAllowedAmount);
    error InvalidAmount(uint256 amount);

    function __ERC20ControlerMinter_init(string memory name, string memory symbol) public onlyInitializing {
        __ERC20_init(name, symbol);
        __AccessControlEnumerable_init();
        __ERC20ControlerMinter_init_unchained();
    }

    function __ERC20ControlerMinter_init_unchained() internal onlyInitializing {
//set's MASTER_MINTER as admin of MINTER_ROLE
        _setRoleAdmin(MINTER_ROLE, MASTER_MINTER);
//this function can be only called by DEFAULT_ADMIN_ROLE/OWNER role from Token.sol which should be the admin of MASTER_MINTER role 
//grants MASTER_MINTER role to addr(0)? but why??
        _grantRole(MASTER_MINTER, address(0));

        _operating = true;
        _operatingController = address(0);
    }

    //-------------------------- CONTROLLER LOGIC --------------------------
//q. which role is the admin for CONTROLLER role?
//OWNER role that is set via _grantRole(OWNER, msg.sender); in initialize() of Token.sol contract 
//to add a new account as controller
    function addController(address newController) external {
        grantRole(CONTROLLER, newController);
    }

//to remove an account from controller role
    function removeController(address controller) external {
        revokeRole(CONTROLLER, controller);
    }
// checks whether given account is CONTROLLEr or not
    function isController(address account) public view returns (bool) {
        return hasRole(CONTROLLER, account);
    }

    /**
     * @dev Function to toggle the operating state of the contract.
     * When called by a CONTROLLER, it switches the contract between operating and non-operating states.
     * In non-operating state, certain functions are disabled (e.g., minting and burning).
     */
    function safetySwitch() public {
        if (_operating) {
//initially _operating= true (called 1st time)
//reverts if caller is not a controller
            if (!hasRole(CONTROLLER, _msgSender())) revert NotController(_msgSender());
//make it as non-operating (disabling mint/burn)
            _operating = false;
//sets the _opController = msg.sender (CONTROLLer tht called this function)
            _operatingController = _msgSender();
        }
// ELSe if operating=false (called 2nd time)
         else {
//NOTE: OWNER = DEFAULT_ADMIN_ROLE (Deployer of Token.sol, that calls initialize())
//reverts if caller (doesnt have DEFAULT_ADMIN_ROLE && is not currently the _operatingController)
            if (!hasRole(DEFAULT_ADMIN_ROLE, _msgSender()) && _operatingController != _msgSender())
                revert SafetySwitchOnUnauthorized(_msgSender());
//reset as operating state
            _operating = true;
//reset _operatingController to addr(0)
            _operatingController = address(0);
        }
        emit SwitchOperatingState(_msgSender(), _operating);
    }

    /**
     * @dev Function to check the current operating state of the contract.
     * Returns a tuple containing the operating status, the controler who switched the state, and the lock time.
     */
//qa- comment says, the fn returns locktime, but fn doesn't return it.
    function isOperating() public view returns (bool, address) {
        return (_operating, _operatingController);
    }

    //-------------------------- MINTING LOGIC --------------------------

//revokes current MASTER_MINTER, and assigns the role to a new account
    function setMasterMinter(address newMasterMinter) external {
//get the 0th index account addr from MASTER_MINTER role account list
        address formerMasterMinter = getRoleMember(MASTER_MINTER, 0);
        if (formerMasterMinter == newMasterMinter) revert AlreadyMasterMinter(newMasterMinter);
//below fn call will verify if caller of this fn has the authority to revokeRole for current MASTER_MINTER 
        revokeRole(MASTER_MINTER, formerMasterMinter);
        emit MinterAllowanceUpdated(formerMasterMinter, 0);
        grantRole(MASTER_MINTER, newMasterMinter);
//MASTER_MINTER can mint indefinite amount of EURF tokens from below event emission
        emit MinterAllowanceUpdated(newMasterMinter, type(uint256).max);
    }

//check if account is the current MASTER_MINTER
    function isMasterMinter(address account) public view returns (bool) {
        return hasRole(MASTER_MINTER, account);
    }

    /**
     * @dev Function to add/update a new minter
     * @param minter The address of the minter
     * @param minterAllowedAmount The minting amount allowed for the minter
     */
//updates the minter mappping with it's allowance,
//grants minterrole to an addr
//can be called by MASTER_MINTER role
    function addMinter(address minter, uint256 minterAllowedAmount) external {
        minterAllowed[minter] = minterAllowedAmount;
        grantRole(MINTER_ROLE, minter);
        emit MinterAllowanceUpdated(minter, minterAllowedAmount);
    }

    /**
     * @dev Function to remove a minter
     * @param minter The address of the minter to remove
     */
//resets minterallowance
//revoke role
    function removeMinter(address minter) external {
        minterAllowed[minter] = 0;
        revokeRole(MINTER_ROLE, minter);
        emit MinterAllowanceUpdated(minter, 0);
    }

    /**
     * @dev Function to update the minting allowance of a minter
     * @param minter The address of the minter
     * @param minterAllowedAmount The new minting amount allowed for the minter
     */
//unlike addMinter(), this fn needs the minter to be an existing minter, before updating their allowance
    function updateMintingAllowance(
        address minter,
        uint256 minterAllowedAmount
    ) external virtual onlyRole(MASTER_MINTER) {
        if (!hasRole(MINTER_ROLE, minter)) revert NotMinter(minter);
        minterAllowed[minter] = minterAllowedAmount;
        emit MinterAllowanceUpdated(minter, minterAllowedAmount);
    }
//getter function
    function getMinterAllowance(address minter) public view returns (uint256) {
        return minterAllowed[minter];
    }

    /**
     * @dev Function to mint tokens
     * @param to The address that will receive the minted tokens.
     * @param amount The amount of tokens to mint. Must be less than or equal
     * to the minterAllowance of the caller.
     */
//follows CEI, so no reentrancy possible
//q. is controller more powerful than the MINtER/ MASTER_MINTER role?
// because they can front-run this mint() by safetySwitch() to cause the mint/burn to revert 
    function mint(address to, uint256 amount) public virtual {
        if (!hasRole(MASTER_MINTER, _msgSender()) && !hasRole(MINTER_ROLE, _msgSender()))
            revert NotMinter(_msgSender());
        if (amount <= 0) revert InvalidAmount(amount);
        if (!_operating) revert OperationsOff();

        // MINTER_ROLE allowance management
        if (hasRole(MINTER_ROLE, _msgSender())) {
            uint256 mintingAllowedAmount = minterAllowed[_msgSender()];
            if (amount > mintingAllowedAmount) revert mintingAllowedAmountExceeded(amount, mintingAllowedAmount);
            minterAllowed[_msgSender()] = mintingAllowedAmount - amount;
        }
// mints the amount of tokens to 'to' address
//if to==addr(0), then the the below fn call will revert due to check in _mint()
//below fn call is on ERC20Upgradeable contract
        _mint(to, amount);
        emit Mint(_msgSender(), to, amount);
    }

    /**
     * @dev allows a minter to burn some of its own tokens
     * Validates that caller is a minter and that sender is not blacklisted
     * amount is less than or equal to the minter's account balance
     * @param amount uint256 the amount of tokens to be burned
     */
    function burn(uint256 amount) public virtual {
        if (!hasRole(MASTER_MINTER, _msgSender()) && !hasRole(MINTER_ROLE, _msgSender()))
            revert NotMinter(_msgSender());
        if (!_operating) revert OperationsOff();
        _burn(_msgSender(), amount);
        emit Burn(_msgSender(), amount);
    }
}
