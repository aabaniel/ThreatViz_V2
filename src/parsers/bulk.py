
#===============================================================#

# Comparison Bar

#===============================================================#

def create_comparison_bar(vt_rep, abuse_score, pulse_count):
    fig = plt.figure(figsize=(6,4))
    sources = ["VT Reputation", "AbuseIPDB Score", "OTX Pulses"]
    vals = [float(vt_rep or 0), float(abuse_score or 0), float(pulse_count or 0)]
    bars = plt.bar(sources, vals, color=["#86A9FA", "#29742b", "#090E53"])
    plt.title("Threat Intelligence Comparison")
    plt.ylabel("Score / Count")
    top = max(vals) if any(vals) else 1.0
    for rect, val in zip(bars, vals):
        plt.text(rect.get_x() + rect.get_width()/2, val + max(0.5, 0.02*top),
                 str(val), ha="center", va="bottom")
    return save_fig(fig, "comparison_bar.png")
