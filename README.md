

## Features

- **Multi-Layer Analysis**: Combines URL structure analysis, content pattern detection, domain reputation checks, behavioral monitoring, form security analysis, and certificate validation
- **Real-Time Monitoring**: Continuously monitors page behavior including redirects, popups, clipboard access, and DOM modifications
- **Risk Scoring**: Sophisticated scoring system that weighs multiple factors to provide accurate risk assessments
- **Visual Warnings**: Displays clear, user-friendly warnings for high-risk pages
- **Low False Positives**: Conservative thresholds and weighted analysis reduce false alarms
- **Privacy-Focused**: All analysis performed locally, no data sent to external servers

## Installation

1. Download or clone this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable "Developer mode" in the top-right corner
4. Click "Load unpacked"
5. Select the `scam-detector-extension` directory

## Detection Capabilities

### URL Analysis
- IP address detection in URLs
- Excessive subdomain detection
- Homoglyph and IDN homograph attacks
- Brand impersonation attempts
- Suspicious keyword patterns
- Redirect parameter detection

### Content Analysis
- Urgency-based manipulation tactics
- Sensitive data request patterns
- Spelling and grammar anomalies
- Reward/prize scam indicators

### Domain Reputation
- Known threat database matching
- New domain detection
- High-risk TLD identification

### Behavioral Monitoring
- Automatic redirect attempts
- Excessive popup detection
- Clipboard access monitoring
- Hidden iframe detection

### Form Security
- Insecure form submission detection
- External form action analysis
- Sensitive data transmission checks

### Certificate Validation
- SSL/TLS certificate validity
- Self-signed certificate detection
- Certificate-domain mismatch alerts

## Risk Levels

- **Safe**: No significant concerns detected
- **Low**: Minor issues found, generally safe
- **Medium**: Some concerning patterns, exercise caution
- **High**: Multiple security concerns, recommend leaving
- **Critical**: Strong scam indicators, leave immediately


## Limitations

- Cannot analyze content behind authentication
- Limited to client-side analysis
- Cannot access iframe content from different origins
- Certificate details limited by browser API capabilities

## Future Enhancements

- [ ] Machine learning-based pattern recognition
- [ ] Community-driven threat database
- [ ] Customizable sensitivity levels
- [ ] Whitelist management for trusted sites
- [ ] Export analysis reports

## License

This project is provided as-is for educational and security purposes.

## Disclaimer

This extension provides analysis based on heuristic patterns and should not be considered a replacement for comprehensive security practices. Always exercise caution when providing sensitive information online.
