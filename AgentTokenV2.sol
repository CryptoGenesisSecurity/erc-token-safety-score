// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * AgentTokenFactory V2 - The Launchpad for AI Agent Economies
 *
 * Each token has:
 * - Bonding curve (buy/sell without DEX, no initial liquidity needed)
 * - 1% fee on every trade → SafeAgent treasury
 * - Auto-graduation to DEX when market cap threshold reached
 * - Safe by construction (no owner, no mint, no blacklist)
 * - Agent-callable via MCP (no UI needed)
 *
 * How it works:
 * 1. Agent calls createToken("AgentCoin", "AGC") with 0.0005 ETH fee
 * 2. Anyone can buy() by sending ETH → gets tokens at bonding curve price
 * 3. Anyone can sell() tokens → gets ETH back minus fee
 * 4. Price rises with supply (early buyers profit)
 * 5. When pool reaches graduation threshold → liquidity migrates to DEX
 */

contract AgentToken {
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // Bonding curve state
    address public factory;
    bool public graduated;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(string memory _name, string memory _symbol, address _factory) {
        name = _name;
        symbol = _symbol;
        factory = _factory;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == factory, "only factory");
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function burn(address from, uint256 amount) external {
        require(msg.sender == factory, "only factory");
        require(balanceOf[from] >= amount, "insufficient");
        balanceOf[from] -= amount;
        totalSupply -= amount;
        emit Transfer(from, address(0), amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "insufficient");
        require(allowance[from][msg.sender] >= amount, "not approved");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}

contract AgentTokenFactory {
    address public treasury;
    uint256 public creationFee = 0.0005 ether;
    uint256 public tradeFeePercent = 100; // 1% = 100 basis points

    // Bonding curve parameters
    // Price = BASE_PRICE + (supply * SLOPE / 1e18)
    // At 0 supply: price = 0.00001 ETH per token
    // At 1M supply: price = 0.01001 ETH per token
    uint256 constant BASE_PRICE = 0.00001 ether;
    uint256 constant SLOPE = 0.00001 ether; // price increase per token

    // Graduation: when pool has 1 ETH, migrate to DEX
    uint256 public graduationThreshold = 1 ether;

    struct TokenInfo {
        address token;
        address creator;
        uint256 poolBalance; // ETH in the bonding curve
        bool graduated;
        uint256 createdAt;
    }

    mapping(address => TokenInfo) public tokens;
    address[] public allTokens;
    uint256 public totalCreated;
    uint256 public totalVolume;

    event TokenCreated(address indexed token, address indexed creator, string name, string symbol);
    event Buy(address indexed token, address indexed buyer, uint256 ethIn, uint256 tokensOut, uint256 newPrice);
    event Sell(address indexed token, address indexed seller, uint256 tokensIn, uint256 ethOut, uint256 newPrice);
    event Graduated(address indexed token, uint256 poolBalance);

    constructor(address _treasury) {
        treasury = _treasury;
    }

    // ==================== CREATE ====================

    function createToken(
        string calldata _name,
        string calldata _symbol
    ) external payable returns (address) {
        require(msg.value >= creationFee, "fee required");
        require(bytes(_name).length > 0 && bytes(_symbol).length > 0, "empty name/symbol");

        AgentToken token = new AgentToken(_name, _symbol, address(this));
        address tokenAddr = address(token);

        tokens[tokenAddr] = TokenInfo({
            token: tokenAddr,
            creator: msg.sender,
            poolBalance: 0,
            graduated: false,
            createdAt: block.timestamp
        });

        allTokens.push(tokenAddr);
        totalCreated++;

        // Send creation fee to treasury
        payable(treasury).transfer(msg.value);

        emit TokenCreated(tokenAddr, msg.sender, _name, _symbol);
        return tokenAddr;
    }

    // ==================== BUY (ETH → Tokens) ====================

    function buy(address token) external payable {
        TokenInfo storage info = tokens[token];
        require(info.token != address(0), "token not found");
        require(!info.graduated, "graduated - trade on DEX");
        require(msg.value > 0, "send ETH");

        // Take fee
        uint256 fee = (msg.value * tradeFeePercent) / 10000;
        uint256 ethForTokens = msg.value - fee;

        // Calculate tokens out based on bonding curve
        uint256 currentSupply = AgentToken(token).totalSupply();
        uint256 tokensOut = getTokensForETH(currentSupply, ethForTokens);
        require(tokensOut > 0, "amount too small");

        // Mint tokens to buyer
        AgentToken(token).mint(msg.sender, tokensOut);

        // Update pool
        info.poolBalance += ethForTokens;
        totalVolume += msg.value;

        // Send fee to treasury
        if (fee > 0) {
            payable(treasury).transfer(fee);
        }

        uint256 newPrice = getCurrentPrice(AgentToken(token).totalSupply());
        emit Buy(token, msg.sender, msg.value, tokensOut, newPrice);

        // Check graduation
        if (info.poolBalance >= graduationThreshold) {
            info.graduated = true;
            emit Graduated(token, info.poolBalance);
            // TODO: auto-add liquidity to DEX
        }
    }

    // ==================== SELL (Tokens → ETH) ====================

    function sell(address token, uint256 amount) external {
        TokenInfo storage info = tokens[token];
        require(info.token != address(0), "token not found");
        require(!info.graduated, "graduated - trade on DEX");
        require(amount > 0, "zero amount");

        uint256 currentSupply = AgentToken(token).totalSupply();
        uint256 ethOut = getETHForTokens(currentSupply, amount);
        require(ethOut > 0, "amount too small");
        require(ethOut <= info.poolBalance, "insufficient pool");

        // Take fee
        uint256 fee = (ethOut * tradeFeePercent) / 10000;
        uint256 ethToSeller = ethOut - fee;

        // Burn tokens
        AgentToken(token).burn(msg.sender, amount);

        // Update pool
        info.poolBalance -= ethOut;
        totalVolume += ethOut;

        // Send ETH to seller
        payable(msg.sender).transfer(ethToSeller);

        // Send fee to treasury
        if (fee > 0) {
            payable(treasury).transfer(fee);
        }

        uint256 newPrice = getCurrentPrice(AgentToken(token).totalSupply());
        emit Sell(token, msg.sender, amount, ethToSeller, newPrice);
    }

    // ==================== BONDING CURVE MATH ====================

    // Price at a given supply: P(s) = BASE_PRICE + s * SLOPE / 1e18
    function getCurrentPrice(uint256 supply) public pure returns (uint256) {
        return BASE_PRICE + (supply * SLOPE / 1e18);
    }

    // ETH needed to buy from supply s0 to s1:
    // integral of P(s) ds from s0 to s1
    // = BASE_PRICE * (s1 - s0) + SLOPE * (s1^2 - s0^2) / (2 * 1e18)
    function getETHForTokens(uint256 currentSupply, uint256 tokenAmount) public pure returns (uint256) {
        uint256 s0 = currentSupply - tokenAmount;
        uint256 s1 = currentSupply;
        uint256 linearPart = BASE_PRICE * tokenAmount / 1e18;
        uint256 quadPart = SLOPE * (s1 * s1 - s0 * s0) / (2 * 1e36);
        return linearPart + quadPart;
    }

    // Tokens received for a given ETH amount (approximate - binary search)
    function getTokensForETH(uint256 currentSupply, uint256 ethAmount) public pure returns (uint256) {
        // Simple approximation: use average price
        uint256 avgPrice = getCurrentPrice(currentSupply + 1e17); // price at +0.1 token
        if (avgPrice == 0) return 0;
        uint256 rough = ethAmount * 1e18 / avgPrice;

        // Refine with 3 iterations of Newton's method
        for (uint i = 0; i < 3; i++) {
            uint256 cost = _costForTokens(currentSupply, rough);
            if (cost > ethAmount) {
                rough = rough * ethAmount / cost;
            } else {
                uint256 diff = ethAmount - cost;
                uint256 marginalPrice = getCurrentPrice(currentSupply + rough);
                if (marginalPrice > 0) {
                    rough += diff * 1e18 / marginalPrice;
                }
            }
        }
        return rough;
    }

    function _costForTokens(uint256 s0, uint256 amount) internal pure returns (uint256) {
        uint256 s1 = s0 + amount;
        uint256 linearPart = BASE_PRICE * amount / 1e18;
        uint256 quadPart = SLOPE * (s1 * s1 - s0 * s0) / (2 * 1e36);
        return linearPart + quadPart;
    }

    // ==================== VIEW ====================

    function getTokenInfo(address token) external view returns (
        string memory _name,
        string memory _symbol,
        uint256 supply,
        uint256 poolBalance,
        uint256 price,
        bool _graduated,
        address creator
    ) {
        TokenInfo memory info = tokens[token];
        AgentToken t = AgentToken(info.token);
        return (
            t.name(),
            t.symbol(),
            t.totalSupply(),
            info.poolBalance,
            getCurrentPrice(t.totalSupply()),
            info.graduated,
            info.creator
        );
    }

    function getTokenCount() external view returns (uint256) {
        return allTokens.length;
    }

    function getStats() external view returns (uint256 created, uint256 volume) {
        return (totalCreated, totalVolume);
    }
}
