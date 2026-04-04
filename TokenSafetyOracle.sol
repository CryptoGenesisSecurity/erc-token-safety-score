// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC_TokenSafetyScore {
    event SafetyScoreUpdated(address indexed token, uint8 score, uint256 flags, uint256 updatedAt);
    function getSafetyScore(address token) external view returns (uint8 score, uint256 flags, uint256 updatedAt);
    function isSafe(address token, uint8 minScore) external view returns (bool safe);
    function chainId() external view returns (uint256);
    function operator() external view returns (address);
}

contract TokenSafetyOracle is IERC_TokenSafetyScore {
    address public override operator;
    uint256 public override chainId;

    struct Score {
        uint8 score;
        uint256 flags;
        uint256 updatedAt;
    }

    mapping(address => Score) private _scores;
    uint256 public totalScored;

    modifier onlyOperator() {
        require(msg.sender == operator, "not operator");
        _;
    }

    constructor(uint256 _chainId) {
        operator = msg.sender;
        chainId = _chainId;
    }

    function updateScore(address token, uint8 score, uint256 flags) external onlyOperator {
        require(score <= 100, "score > 100");
        if (_scores[token].updatedAt == 0) totalScored++;
        _scores[token] = Score(score, flags, block.timestamp);
        emit SafetyScoreUpdated(token, score, flags, block.timestamp);
    }

    function batchUpdateScores(
        address[] calldata tokens,
        uint8[] calldata scores,
        uint256[] calldata flags
    ) external onlyOperator {
        require(tokens.length == scores.length && scores.length == flags.length, "length mismatch");
        for (uint i = 0; i < tokens.length; i++) {
            require(scores[i] <= 100, "score > 100");
            if (_scores[tokens[i]].updatedAt == 0) totalScored++;
            _scores[tokens[i]] = Score(scores[i], flags[i], block.timestamp);
            emit SafetyScoreUpdated(tokens[i], scores[i], flags[i], block.timestamp);
        }
    }

    function getSafetyScore(address token) external view override returns (uint8 score, uint256 flags, uint256 updatedAt) {
        Score memory s = _scores[token];
        return (s.score, s.flags, s.updatedAt);
    }

    function isSafe(address token, uint8 minScore) external view override returns (bool safe) {
        return _scores[token].score >= minScore && _scores[token].updatedAt > 0;
    }

    function transferOperator(address newOperator) external onlyOperator {
        operator = newOperator;
    }
}
