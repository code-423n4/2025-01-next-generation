// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";

abstract contract ERC20AdminUpgradeable is ERC20Upgradeable, PausableUpgradeable, AccessControlEnumerableUpgradeable {
    bytes32 public constant ADMIN = keccak256("ADMIN");

    mapping(address => bool) private _blacklist;

    event Blacklisted(address account, bool blacklisted);

    error PausedError();
    error BlacklistUnchangedError(address account, bool blacklisted);
    error SenderBlacklistedError(address account);
    error RecipientBlacklistedError(address account);
    error TransferToContractError();

    event ForcedTransfer(address indexed from, address indexed to, uint256 amount);
//The onlyInitializing modifier ensures that when the initialize function is called, any contracts in its inheritance chain can still complete their own initialization.
//issue- The following fn is nowhere called and should be called from it's child class (Token.sol)
    function __ERC20Admin_init(string memory name, string memory symbol) internal onlyInitializing {
        __ERC20_init(name, symbol);   // calls __ERC20_init_unchained(name,symbol), being called directly in Token.sol initiailize()      
        __Pausable_init();  //called from child initialize()
        __AccessControlEnumerable_init(); //called from child initialize()
        __ERC20Admin_init_unchained(); //called from child initialize()
    }

    function __ERC20Admin_init_unchained() internal onlyInitializing {
        _grantRole(ADMIN, address(0));
    }
// fn to set a new admin
    function setAdministrator(address newAdmin) external onlyRole(DEFAULT_ADMIN_ROLE) {
//revokeRole for current admin
//getRoleMember(ADMIN,0) returns the 1st account that have ADMIN role in list of admin roles
        revokeRole(ADMIN, getRoleMember(ADMIN, 0));
//grants admin role to new Admin account
        grantRole(ADMIN, newAdmin);
    }
//fn to check if an account has admin role or not T/F
    function isAdministrator(address account) public view returns (bool) {
        return hasRole(ADMIN, account);
    }

    //-------------------------- BLACKLIST LOGIC --------------------------

//fn to add/remove an account from blackListed accounts
    function setBlacklist(address account, bool blacklisted) internal onlyRole(ADMIN) {
        if (_blacklist[account] == blacklisted) revert BlacklistUnchangedError(account, blacklisted);
        _blacklist[account] = blacklisted;
        emit Blacklisted(account, blacklisted);
    }
//external fn to be only called by ADMIN
    function blacklist(address account) external {
        setBlacklist(account, true);
    }
//external fn to be only called by ADMIN
    function unblacklist(address account) external {
        setBlacklist(account, false);
    }
//getter fn to check if an account is blacklisted
    function isBlacklisted(address account) public view returns (bool) {
        return _blacklist[account];
    }

    //-------------------------- PAUSE LOGIC -----------------------------

    function pause() external onlyRole(ADMIN) {
        _pause();
    }

    function unpause() external onlyRole(ADMIN) {
        _unpause();
    }

    //-------------------------- TRANSFER LOGIC --------------------------
//does following checks:
//if contract is paused - revert
//if caller isBlacklisted- revert
//if to is blakclisted- revert
//if to = this contracrt address- revert
    function adminSanity(address from, address to) internal view {
        if (!hasRole(ADMIN, _msgSender())) {
            if (paused()) revert PausedError();
            if (isBlacklisted(from)) revert SenderBlacklistedError(from);
        }
        if (isBlacklisted(to)) revert RecipientBlacklistedError(to);
        if (to == address(this)) revert TransferToContractError();
    }

// admin function to forcefully cause ERC20 transfer of EURF from to to address
    function forceTransfer(address from, address to, uint256 amount) external onlyRole(ADMIN) {
        adminSanity(from, to);
        _update(from, to, amount);
        emit ForcedTransfer(from, to, amount);
    }
}
