"""
SafeAgent + LangChain: Add token safety checks to any AI trading agent.

pip install langchain safeagent
"""
from langchain.tools import tool
from safeagent import check_token, is_safe


@tool
def check_token_safety(address: str, chain: str = "base") -> str:
    """Check if a crypto token is safe before trading.
    Use this BEFORE any buy/swap operation.

    Args:
        address: Token contract address (0x...)
        chain: base, ethereum, arbitrum, optimism, polygon, bsc
    """
    result = check_token(address, chain)
    score = result.get("safety_score", 0)
    verdict = result.get("verdict", "UNKNOWN")
    flags = result.get("flags", [])
    token = result.get("token", {})

    report = f"Token: {token.get('name', '?')} ({token.get('symbol', '?')})\n"
    report += f"Safety Score: {score}/100 — {verdict}\n"

    if flags:
        report += f"Risk Flags: {', '.join(flags)}\n"

    if score < 40:
        report += "\n⚠️ DO NOT BUY — High probability of scam."
    elif score < 70:
        report += "\n⚠️ CAUTION — Proceed with reduced position."

    return report


# Usage with any LangChain agent:
#
# from langchain.agents import initialize_agent, AgentType
# from langchain_openai import ChatOpenAI
#
# llm = ChatOpenAI(model="gpt-4o")
# agent = initialize_agent(
#     tools=[check_token_safety],
#     llm=llm,
#     agent=AgentType.OPENAI_FUNCTIONS,
# )
# agent.run("Is 0x532f27101965dd16442E59d40670FaF5eBB142E4 safe on base?")
