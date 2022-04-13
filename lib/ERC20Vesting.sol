// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./ERC20Fee.sol";
import "../lib/errors.sol";

error VestingToSelf();
error VestingToTokenContract();
error VestingNotRevokable();
error VestingLimitPerAddress();
error VestingWrongDates();
error NonTransferableAmount();

abstract contract ERC20Vesting is ERC20Fee {
    uint256 public constant MAX_VESTINGS_PER_ADDRESS = 50;

    event AssignVested(address indexed receiver, uint256 vestingId, uint256 amount);
    event RevokeVested(address indexed receiver, uint256 vestingId, uint256 nonVestedAmount);

    struct TokenVesting {
        uint256 amount; // The total amount of tokens vested
        uint64 start; // The vesting start time
        uint64 cliff; // The cliff period
        uint64 vested; // The fully vested date
        bool revokable; // Flag, allow to revoke vested tokens
    }

    // We are mimicing an array in the inner mapping, we use a mapping instead to make app upgrade more graceful
    mapping(address => mapping(uint256 => TokenVesting)) private _vestings;
    mapping(address => uint256) private _vestingsCounts;

    modifier vestingExists(address holder, uint256 vestingId) {
        // TODO: it's not checking for gaps that may appear because of deletes in revokeVesting function
        if (vestingId >= _vestingsCounts[holder]) revert NotExists();
        _;
    }

    function getVesting(address holder, uint256 vestingId)
        external
        view
        virtual
        vestingExists(holder, vestingId)
        returns (
            uint256 amount,
            uint64 start,
            uint64 cliff,
            uint64 vested,
            bool revokable
        )
    {
        TokenVesting storage tokenVesting = _vestings[holder][vestingId];
        amount = tokenVesting.amount;
        start = tokenVesting.start;
        cliff = tokenVesting.cliff;
        vested = tokenVesting.vested;
        revokable = tokenVesting.revokable;
    }

    function getVestingCount(address holder) external view virtual returns (uint256 count) {
        return _vestingsCounts[holder];
    }

    function spendableBalanceOf(address _holder) external view virtual returns (uint256) {
        return _transferableBalance(_holder, block.timestamp);
    }

    /**
     * @notice Assign `@tokenAmount(self.token(): address, amount, false)` tokens to `receiver` from the Token Manager's holdings with a `revokable : 'revokable' : ''` vested starting at `@formatDate(start)`, cliff at `@formatDate(cliff)` (first portion of tokens transferable), and completed vesting at `@formatDate(vested)` (all tokens transferable)
     * @param receiver The address receiving the tokens, cannot be Token itself
     * @param amount Number of tokens vested
     * @param start Date the vesting calculations start
     * @param cliff Date when the initial portion of tokens are transferable
     * @param vested Date when all tokens are transferable
     * @param revokable Whether the vesting can be revoked by the Token Manager
     */
    function _assignVested(
        address sender,
        address receiver,
        uint256 amount,
        uint64 start,
        uint64 cliff,
        uint64 vested,
        bool revokable
    ) internal virtual returns (uint256) {
        if (receiver == sender) revert VestingToSelf();
        if (_vestingsCounts[receiver] >= MAX_VESTINGS_PER_ADDRESS) revert VestingLimitPerAddress();
        if (cliff < start || cliff > vested) revert VestingWrongDates();

        uint256 vestingId = _vestingsCounts[receiver]++;
        _vestings[receiver][vestingId] = TokenVesting(amount, start, cliff, vested, revokable);
        _transfer(sender, receiver, amount);

        emit AssignVested(receiver, vestingId, amount);

        return vestingId;
    }

    /**
     * @notice Revoke vesting #`vestingId` from `holder`, returning unvested tokens to the Token Manager
     * @param holder Address whose vesting to revoke
     * @param vestingId Numeric id of the vesting
     */
    function _revokeVested(address holder, uint256 vestingId) internal virtual vestingExists(holder, vestingId) {
        TokenVesting memory v = _vestings[holder][vestingId];
        if (!v.revokable) revert VestingNotRevokable();

        uint256 nonVested = _calculateNonVestedTokens(v, block.timestamp);

        // To make vestingIds immutable over time, we just zero out the revoked vesting
        // Clearing this out also allows the token transfer back to the Token Manager to succeed
        delete _vestings[holder][vestingId];

        _transfer(holder, address(this), nonVested);

        emit RevokeVested(holder, vestingId, nonVested);
    }

    /**
     * @dev Calculate amount of non-vested tokens at a specifc time
     * @param v TokenVesting structure
     * @param time The time at which to check
     * @return The amount of non-vested tokens of a specific grant
     *  transferableTokens
     *   |                         _/--------   vestedTokens rect
     *   |                       _/
     *   |                     _/
     *   |                   _/
     *   |                 _/
     *   |                /
     *   |              .|
     *   |            .  |
     *   |          .    |
     *   |        .      |
     *   |      .        |
     *   |    .          |
     *   +===+===========+---------+----------> time
     *      Start       Cliff    Vested
     */
    function _calculateNonVestedTokens(TokenVesting memory v, uint256 time) private pure returns (uint256) {
        // Shortcuts for before cliff and after vested cases.
        if (time >= v.vested) {
            return 0;
        }
        if (time < v.cliff) {
            return v.amount;
        }

        // Interpolate all vested tokens.
        // As before cliff the shortcut returns 0, we can just calculate a value
        // in the vesting rect (as shown in above's figure)

        // In assignVesting we enforce start <= cliff <= vested
        // Here we shortcut time >= vested and time < cliff,
        // so no division by 0 is possible
        uint256 vestedTokens = (v.amount * (time - v.start)) / (v.vested - v.start);

        // tokens - vestedTokens
        return v.amount - vestedTokens;
    }

    function _transferableBalance(address holder, uint256 time) internal view virtual returns (uint256) {
        uint256 transferable = super.balanceOf(holder);
        uint256 vestingsCount = _vestingsCounts[holder];
        for (uint256 i = 0; i < vestingsCount; i++) {
            TokenVesting memory v = _vestings[holder][i];
            uint256 nonTransferable = _calculateNonVestedTokens(v, time);
            transferable -= nonTransferable;
        }
        return transferable;
    }

    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 amount
    ) internal virtual override {
        super._beforeTokenTransfer(from, to, amount);
        if (from != address(0) && _vestingsCounts[from] > 0 && _transferableBalance(from, block.timestamp) < amount) {
            revert NonTransferableAmount();
        }
    }

    /**
     * @notice Batch token transfer to list of receivers
     * @param receivers Addresses array of receivers
     * @param amounts Toen amounts array
     */
    function _distribute(address[] memory receivers, uint256[] memory amounts) internal virtual {
        if (receivers.length != amounts.length) revert WrongInputParams();
        for (uint256 i = 0; i < receivers.length; i++) {
            _transfer(address(this), receivers[i], amounts[i]);
        }
    }

    /**
     * @notice Batch assigninig vested tokens. See {ERC20Vesting-_assignVested}.
     */
    function _distributeVested(
        address[] memory receivers,
        uint256[] memory amounts,
        uint64 start,
        uint64 cliff,
        uint64 vested,
        bool revokable
    ) internal virtual {
        if (receivers.length != amounts.length) revert WrongInputParams();
        for (uint256 i = 0; i < receivers.length; i++) {
            _assignVested(address(this), receivers[i], amounts[i], start, cliff, vested, revokable);
        }
    }
}
