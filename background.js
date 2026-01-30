const CACHE_DURATION = 3600000;
const ANALYSIS_DEBOUNCE = 500;

const knownScamPatterns = {
  domains: new Set(),
  lastUpdate: 0
};

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({
    analysisHistory: {},
    settings: {
      sensitivityLevel: 'medium',
      enableNotifications: true,
      trustedDomains: []
    }
  });
  
  updateThreatDatabase();
});

chrome.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId === 0) {
    chrome.tabs.sendMessage(details.tabId, {
      action: 'analyzePageLoad',
      url: details.url
    }).catch(() => {});
  }
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'analyzeContent') {
    handleAnalysisRequest(request.data, sender.tab)
      .then(result => sendResponse({ success: true, result }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true;
  }
  
  if (request.action === 'updateBadge') {
    updateExtensionBadge(sender.tab.id, request.riskLevel);
  }
  
  if (request.action === 'getThreatData') {
    sendResponse({ patterns: Array.from(knownScamPatterns.domains) });
  }
});

async function handleAnalysisRequest(data, tab) {
  const cached = await checkCache(data.url);
  if (cached && Date.now() - cached.timestamp < CACHE_DURATION) {
    return cached.result;
  }
  
  const result = await performComprehensiveAnalysis(data);
  
  await cacheResult(data.url, result);
  
  if (result.riskLevel === 'high' || result.riskLevel === 'critical') {
    const settings = await chrome.storage.local.get('settings');
    if (settings.settings?.enableNotifications) {
      notifyUser(tab, result);
    }
  }
  
  return result;
}

async function performComprehensiveAnalysis(data) {
  const scores = {
    urlAnalysis: analyzeUrlStructure(data.url),
    contentAnalysis: analyzeContentPatterns(data.content),
    domainReputation: await checkDomainReputation(data.domain),
    behavioralAnalysis: analyzeBehavioralIndicators(data.behavioral),
    formAnalysis: analyzeFormSecurity(data.forms),
    certificateAnalysis: analyzeCertificate(data.certificate)
  };
  
  const weights = {
    urlAnalysis: 0.20,
    contentAnalysis: 0.25,
    domainReputation: 0.25,
    behavioralAnalysis: 0.15,
    formAnalysis: 0.10,
    certificateAnalysis: 0.05
  };
  
  let totalScore = 0;
  let totalWeight = 0;
  const findings = [];
  
  for (const [key, score] of Object.entries(scores)) {
    if (score !== null) {
      totalScore += score.value * weights[key];
      totalWeight += weights[key];
      if (score.findings) {
        findings.push(...score.findings);
      }
    }
  }
  
  const normalizedScore = totalWeight > 0 ? totalScore / totalWeight : 0;
  const riskLevel = calculateRiskLevel(normalizedScore, findings);
  
  return {
    riskLevel,
    score: Math.round(normalizedScore * 100),
    findings: findings.sort((a, b) => b.severity - a.severity),
    timestamp: Date.now()
  };
}

function analyzeUrlStructure(url) {
  let suspicionScore = 0;
  const findings = [];
  
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();
    
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipRegex.test(hostname)) {
      suspicionScore += 40;
      findings.push({
        type: 'url_ip_address',
        severity: 7,
        description: 'URL uses IP address instead of domain name'
      });
    }
    
    const excessiveSubdomains = hostname.split('.').length > 4;
    if (excessiveSubdomains) {
      suspicionScore += 20;
      findings.push({
        type: 'excessive_subdomains',
        severity: 5,
        description: 'Unusual number of subdomains detected'
      });
    }
    
    const homoglyphs = detectHomoglyphs(hostname);
    if (homoglyphs.length > 0) {
      suspicionScore += 50;
      findings.push({
        type: 'homoglyph_attack',
        severity: 9,
        description: `Suspicious characters detected: ${homoglyphs.join(', ')}`
      });
    }
    
    const commonBrands = ['paypal', 'amazon', 'microsoft', 'google', 'apple', 'facebook', 'netflix', 'banking', 'secure'];
    for (const brand of commonBrands) {
      if (hostname.includes(brand) && !isLegitimateVariant(hostname, brand)) {
        suspicionScore += 35;
        findings.push({
          type: 'brand_impersonation',
          severity: 8,
          description: `Possible impersonation of ${brand}`
        });
        break;
      }
    }
    
    const suspiciousPatterns = ['-login', 'verify-', 'secure-', 'account-', 'update-'];
    for (const pattern of suspiciousPatterns) {
      if (hostname.includes(pattern)) {
        suspicionScore += 15;
        findings.push({
          type: 'suspicious_keyword',
          severity: 4,
          description: `Suspicious pattern in URL: ${pattern}`
        });
      }
    }
    
    if (urlObj.pathname.length > 100) {
      suspicionScore += 10;
      findings.push({
        type: 'excessive_path_length',
        severity: 3,
        description: 'Unusually long URL path'
      });
    }
    
    const urlParams = urlObj.searchParams;
    if (urlParams.has('redirect') || urlParams.has('url') || urlParams.has('next')) {
      suspicionScore += 15;
      findings.push({
        type: 'redirect_parameter',
        severity: 5,
        description: 'URL contains redirect parameters'
      });
    }
    
  } catch (e) {
    suspicionScore += 30;
    findings.push({
      type: 'malformed_url',
      severity: 6,
      description: 'URL structure is malformed or invalid'
    });
  }
  
  return {
    value: Math.min(suspicionScore / 100, 1),
    findings
  };
}

function analyzeContentPatterns(content) {
  if (!content) return { value: 0, findings: [] };
  
  let suspicionScore = 0;
  const findings = [];
  
  const urgencyPhrases = [
    'act now', 'urgent action required', 'immediate action', 
    'verify your account', 'suspended account', 'unusual activity',
    'confirm your identity', 'limited time', 'expires today',
    'click here immediately', 'verify within 24 hours'
  ];
  
  let urgencyCount = 0;
  for (const phrase of urgencyPhrases) {
    const regex = new RegExp(phrase, 'gi');
    const matches = content.match(regex);
    if (matches) {
      urgencyCount += matches.length;
    }
  }
  
  if (urgencyCount >= 3) {
    suspicionScore += 40;
    findings.push({
      type: 'urgency_manipulation',
      severity: 7,
      description: `Multiple urgency phrases detected (${urgencyCount} instances)`
    });
  } else if (urgencyCount > 0) {
    suspicionScore += 15;
    findings.push({
      type: 'urgency_language',
      severity: 4,
      description: 'Urgency-based language present'
    });
  }
  
  const financialKeywords = [
    'bank account', 'credit card', 'social security', 'password',
    'pin number', 'account number', 'routing number', 'cvv'
  ];
  
  let sensitiveRequestCount = 0;
  for (const keyword of financialKeywords) {
    if (content.toLowerCase().includes(keyword)) {
      sensitiveRequestCount++;
    }
  }
  
  if (sensitiveRequestCount >= 3) {
    suspicionScore += 30;
    findings.push({
      type: 'sensitive_data_request',
      severity: 8,
      description: 'Requests multiple types of sensitive information'
    });
  }
  
  const spellingErrors = detectSpellingAnomalies(content);
  if (spellingErrors > 5) {
    suspicionScore += 25;
    findings.push({
      type: 'poor_quality',
      severity: 5,
      description: `Numerous spelling or grammar issues detected (${spellingErrors})`
    });
  }
  
  const rewardPhrases = ['you have won', 'congratulations', 'free gift', 'claim your prize', 'winner'];
  for (const phrase of rewardPhrases) {
    if (content.toLowerCase().includes(phrase)) {
      suspicionScore += 20;
      findings.push({
        type: 'reward_bait',
        severity: 6,
        description: 'Contains unrealistic reward or prize claims'
      });
      break;
    }
  }
  
  return {
    value: Math.min(suspicionScore / 100, 1),
    findings
  };
}

async function checkDomainReputation(domain) {
  if (!domain) return { value: 0, findings: [] };
  
  let suspicionScore = 0;
  const findings = [];
  
  if (knownScamPatterns.domains.has(domain)) {
    suspicionScore += 90;
    findings.push({
      type: 'known_threat',
      severity: 10,
      description: 'Domain matches known threat database'
    });
  }
  
  const domainAge = estimateDomainAge(domain);
  if (domainAge !== null && domainAge < 30) {
    suspicionScore += 40;
    findings.push({
      type: 'new_domain',
      severity: 7,
      description: `Domain appears to be recently registered (${domainAge} days)`
    });
  }
  
  const tld = domain.split('.').pop();
  const suspiciousTlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work'];
  if (suspiciousTlds.includes(tld)) {
    suspicionScore += 20;
    findings.push({
      type: 'suspicious_tld',
      severity: 5,
      description: `Domain uses high-risk TLD: .${tld}`
    });
  }
  
  return {
    value: Math.min(suspicionScore / 100, 1),
    findings
  };
}

function analyzeBehavioralIndicators(behavioral) {
  if (!behavioral) return { value: 0, findings: [] };
  
  let suspicionScore = 0;
  const findings = [];
  
  if (behavioral.autoRedirects > 0) {
    suspicionScore += 30;
    findings.push({
      type: 'automatic_redirect',
      severity: 7,
      description: `Page attempts automatic redirects (${behavioral.autoRedirects} detected)`
    });
  }
  
  if (behavioral.popups > 2) {
    suspicionScore += 25;
    findings.push({
      type: 'excessive_popups',
      severity: 6,
      description: `Multiple popup attempts detected (${behavioral.popups})`
    });
  }
  
  if (behavioral.clipboardAccess) {
    suspicionScore += 35;
    findings.push({
      type: 'clipboard_access',
      severity: 8,
      description: 'Page attempts to access clipboard'
    });
  }
  
  if (behavioral.hiddenIframes > 0) {
    suspicionScore += 40;
    findings.push({
      type: 'hidden_iframe',
      severity: 8,
      description: `Hidden iframes detected (${behavioral.hiddenIframes})`
    });
  }
  
  return {
    value: Math.min(suspicionScore / 100, 1),
    findings
  };
}

function analyzeFormSecurity(forms) {
  if (!forms || forms.length === 0) return { value: 0, findings: [] };
  
  let suspicionScore = 0;
  const findings = [];
  
  for (const form of forms) {
    if (form.requestsSensitiveData && form.protocol !== 'https') {
      suspicionScore += 60;
      findings.push({
        type: 'insecure_sensitive_form',
        severity: 10,
        description: 'Form requests sensitive data over insecure connection'
      });
    }
    
    if (form.action && form.action.includes('http://')) {
      suspicionScore += 30;
      findings.push({
        type: 'insecure_form_action',
        severity: 7,
        description: 'Form submits to insecure HTTP endpoint'
      });
    }
    
    if (form.externalAction) {
      suspicionScore += 20;
      findings.push({
        type: 'external_form_action',
        severity: 6,
        description: 'Form submits to external domain'
      });
    }
  }
  
  return {
    value: Math.min(suspicionScore / 100, 1),
    findings
  };
}

function analyzeCertificate(certificate) {
  if (!certificate) return { value: 0, findings: [] };
  
  let suspicionScore = 0;
  const findings = [];
  
  if (!certificate.valid) {
    suspicionScore += 70;
    findings.push({
      type: 'invalid_certificate',
      severity: 9,
      description: 'SSL/TLS certificate is invalid or expired'
    });
  }
  
  if (certificate.selfSigned) {
    suspicionScore += 50;
    findings.push({
      type: 'self_signed_certificate',
      severity: 8,
      description: 'Certificate is self-signed'
    });
  }
  
  if (certificate.mismatch) {
    suspicionScore += 60;
    findings.push({
      type: 'certificate_mismatch',
      severity: 9,
      description: 'Certificate does not match domain'
    });
  }
  
  return {
    value: Math.min(suspicionScore / 100, 1),
    findings
  };
}

function calculateRiskLevel(score, findings) {
  const criticalFindings = findings.filter(f => f.severity >= 9).length;
  const highFindings = findings.filter(f => f.severity >= 7).length;
  
  if (criticalFindings >= 2 || score >= 0.8) {
    return 'critical';
  } else if (criticalFindings >= 1 || highFindings >= 2 || score >= 0.6) {
    return 'high';
  } else if (highFindings >= 1 || score >= 0.4) {
    return 'medium';
  } else if (score >= 0.2) {
    return 'low';
  }
  return 'safe';
}

function detectHomoglyphs(text) {
  const homoglyphMap = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
    'ı': 'i', 'ο': 'o', 'ν': 'v', 'α': 'a', 'ε': 'e'
  };
  
  const detected = [];
  for (let i = 0; i < text.length; i++) {
    if (homoglyphMap[text[i]]) {
      detected.push(text[i]);
    }
  }
  return detected;
}

function isLegitimateVariant(hostname, brand) {
  const legitimateDomains = {
    'paypal': ['paypal.com', 'paypal.me'],
    'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr'],
    'google': ['google.com', 'googleapis.com', 'googleusercontent.com'],
    'microsoft': ['microsoft.com', 'live.com', 'outlook.com'],
    'apple': ['apple.com', 'icloud.com']
  };
  
  if (legitimateDomains[brand]) {
    return legitimateDomains[brand].some(domain => hostname.endsWith(domain));
  }
  
  return false;
}

function detectSpellingAnomalies(text) {
  const commonMisspellings = [
    /acc[o0]unt/gi, /secur[i1]ty/gi, /ver[i1]fy/gi, /upd[a4]te/gi,
    /c[o0]nfirm/gi, /b[a4]nk/gi, /p[a4]ssw[o0]rd/gi
  ];
  
  let errors = 0;
  for (const pattern of commonMisspellings) {
    const matches = text.match(pattern);
    if (matches) {
      errors += matches.length;
    }
  }
  
  return errors;
}

function estimateDomainAge(domain) {
  const newDomainPatterns = [
    /\d{4,}/,
    /-\d+-/,
    /temp/i,
    /test/i
  ];
  
  for (const pattern of newDomainPatterns) {
    if (pattern.test(domain)) {
      return 15;
    }
  }
  
  return null;
}

async function checkCache(url) {
  const history = await chrome.storage.local.get('analysisHistory');
  return history.analysisHistory?.[url] || null;
}

async function cacheResult(url, result) {
  const history = await chrome.storage.local.get('analysisHistory');
  const updated = history.analysisHistory || {};
  updated[url] = {
    result,
    timestamp: Date.now()
  };
  
  const entries = Object.entries(updated);
  if (entries.length > 100) {
    entries.sort((a, b) => b[1].timestamp - a[1].timestamp);
    const trimmed = Object.fromEntries(entries.slice(0, 100));
    await chrome.storage.local.set({ analysisHistory: trimmed });
  } else {
    await chrome.storage.local.set({ analysisHistory: updated });
  }
}

function updateExtensionBadge(tabId, riskLevel) {
  const badgeConfig = {
    'critical': { color: '#D32F2F', text: '!' },
    'high': { color: '#F57C00', text: '!' },
    'medium': { color: '#FFA000', text: '?' },
    'low': { color: '#388E3C', text: '✓' },
    'safe': { color: '#4CAF50', text: '✓' }
  };
  
  const config = badgeConfig[riskLevel] || badgeConfig['safe'];
  
  chrome.action.setBadgeBackgroundColor({ color: config.color, tabId });
  chrome.action.setBadgeText({ text: config.text, tabId });
}

function notifyUser(tab, result) {
  chrome.tabs.sendMessage(tab.id, {
    action: 'showWarning',
    data: result
  }).catch(() => {});
}

async function updateThreatDatabase() {
  const knownThreats = [
    'phishing-example.com',
    'scam-site.xyz',
    'fake-banking.tk'
  ];
  
  knownScamPatterns.domains = new Set(knownThreats);
  knownScamPatterns.lastUpdate = Date.now();
}

setInterval(() => {
  if (Date.now() - knownScamPatterns.lastUpdate > 86400000) {
    updateThreatDatabase();
  }
}, 3600000);
