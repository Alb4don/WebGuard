let analysisInProgress = false;
let pageData = {
  url: window.location.href,
  domain: window.location.hostname,
  protocol: window.location.protocol,
  content: '',
  forms: [],
  behavioral: {
    autoRedirects: 0,
    popups: 0,
    clipboardAccess: false,
    hiddenIframes: 0
  },
  certificate: null
};

function initialize() {
  if (window.location.protocol === 'chrome:' || 
      window.location.protocol === 'chrome-extension:' ||
      window.location.protocol === 'about:') {
    return;
  }
  
  collectPageData();
  setupMonitors();
  performAnalysis();
}

function collectPageData() {
  pageData.content = extractTextContent();
  pageData.forms = analyzeForms();
  pageData.behavioral.hiddenIframes = detectHiddenIframes();
  pageData.certificate = getCertificateInfo();
}

function extractTextContent() {
  const clone = document.body.cloneNode(true);
  
  const scripts = clone.querySelectorAll('script, style, noscript');
  scripts.forEach(el => el.remove());
  
  let text = clone.textContent || clone.innerText || '';
  text = text.replace(/\s+/g, ' ').trim();
  
  return text.substring(0, 10000);
}

function analyzeForms() {
  const forms = document.querySelectorAll('form');
  const formData = [];
  
  forms.forEach(form => {
    const inputs = form.querySelectorAll('input, textarea, select');
    let requestsSensitiveData = false;
    
    inputs.forEach(input => {
      const type = (input.type || '').toLowerCase();
      const name = (input.name || '').toLowerCase();
      const id = (input.id || '').toLowerCase();
      
      const sensitiveFields = [
        'password', 'credit', 'card', 'cvv', 'ssn', 
        'social', 'account', 'routing', 'pin'
      ];
      
      for (const field of sensitiveFields) {
        if (type.includes(field) || name.includes(field) || id.includes(field)) {
          requestsSensitiveData = true;
          break;
        }
      }
    });
    
    const action = form.action || '';
    let externalAction = false;
    
    if (action) {
      try {
        const actionUrl = new URL(action, window.location.href);
        externalAction = actionUrl.hostname !== window.location.hostname;
      } catch (e) {
        externalAction = true;
      }
    }
    
    formData.push({
      action: action,
      method: form.method || 'get',
      requestsSensitiveData: requestsSensitiveData,
      protocol: window.location.protocol,
      externalAction: externalAction
    });
  });
  
  return formData;
}

function detectHiddenIframes() {
  const iframes = document.querySelectorAll('iframe');
  let hiddenCount = 0;
  
  iframes.forEach(iframe => {
    const style = window.getComputedStyle(iframe);
    const rect = iframe.getBoundingClientRect();
    
    if (style.display === 'none' || 
        style.visibility === 'hidden' ||
        rect.width === 0 || 
        rect.height === 0 ||
        parseFloat(style.opacity) === 0) {
      hiddenCount++;
    }
  });
  
  return hiddenCount;
}

function getCertificateInfo() {
  if (window.location.protocol !== 'https:') {
    return {
      valid: false,
      selfSigned: false,
      mismatch: false
    };
  }
  
  return {
    valid: true,
    selfSigned: false,
    mismatch: false
  };
}

function setupMonitors() {
  monitorRedirects();
  monitorPopups();
  monitorClipboard();
  monitorDOMChanges();
}

function monitorRedirects() {
  const originalReplace = window.location.replace;
  const originalAssign = window.location.assign;
  
  window.location.replace = function(...args) {
    pageData.behavioral.autoRedirects++;
    triggerReanalysis();
    return originalReplace.apply(this, args);
  };
  
  window.location.assign = function(...args) {
    pageData.behavioral.autoRedirects++;
    triggerReanalysis();
    return originalAssign.apply(this, args);
  };
  
  const metaRefresh = document.querySelector('meta[http-equiv="refresh"]');
  if (metaRefresh) {
    pageData.behavioral.autoRedirects++;
  }
}

function monitorPopups() {
  const originalOpen = window.open;
  
  window.open = function(...args) {
    pageData.behavioral.popups++;
    triggerReanalysis();
    return originalOpen.apply(this, args);
  };
  
  const originalAlert = window.alert;
  window.alert = function(...args) {
    pageData.behavioral.popups++;
    triggerReanalysis();
    return originalAlert.apply(this, args);
  };
}

function monitorClipboard() {
  const clipboardEvents = ['copy', 'cut', 'paste'];
  
  clipboardEvents.forEach(eventType => {
    document.addEventListener(eventType, (e) => {
      if (e.isTrusted && !e.target.closest('input, textarea')) {
        pageData.behavioral.clipboardAccess = true;
        triggerReanalysis();
      }
    }, true);
  });
}

function monitorDOMChanges() {
  const observer = new MutationObserver((mutations) => {
    let significantChange = false;
    
    for (const mutation of mutations) {
      if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
        for (const node of mutation.addedNodes) {
          if (node.nodeName === 'IFRAME' || node.nodeName === 'FORM') {
            significantChange = true;
            break;
          }
        }
      }
    }
    
    if (significantChange) {
      setTimeout(() => {
        collectPageData();
        triggerReanalysis();
      }, 1000);
    }
  });
  
  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
}

let reanalysisTimeout = null;

function triggerReanalysis() {
  if (reanalysisTimeout) {
    clearTimeout(reanalysisTimeout);
  }
  
  reanalysisTimeout = setTimeout(() => {
    performAnalysis();
  }, 2000);
}

async function performAnalysis() {
  if (analysisInProgress) return;
  
  analysisInProgress = true;
  
  try {
    const response = await chrome.runtime.sendMessage({
      action: 'analyzeContent',
      data: pageData
    });
    
    if (response.success) {
      handleAnalysisResult(response.result);
    }
  } catch (error) {
    console.error('Analysis failed:', error);
  } finally {
    analysisInProgress = false;
  }
}

function handleAnalysisResult(result) {
  chrome.runtime.sendMessage({
    action: 'updateBadge',
    riskLevel: result.riskLevel
  });
  
  if (result.riskLevel === 'critical' || result.riskLevel === 'high') {
    displayWarningOverlay(result);
  }
}

function displayWarningOverlay(result) {
  const existingOverlay = document.getElementById('webguard-warning-overlay');
  if (existingOverlay) {
    existingOverlay.remove();
  }
  
  const overlay = document.createElement('div');
  overlay.id = 'webguard-warning-overlay';
  overlay.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.85);
    z-index: 2147483647;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  `;
  
  const warningBox = document.createElement('div');
  warningBox.style.cssText = `
    background: white;
    border-radius: 12px;
    padding: 32px;
    max-width: 600px;
    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
  `;
  
  const severityColor = result.riskLevel === 'critical' ? '#D32F2F' : '#F57C00';
  
  const icon = document.createElement('div');
  icon.style.cssText = `
    width: 64px;
    height: 64px;
    background: ${severityColor};
    border-radius: 50%;
    margin: 0 auto 20px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 36px;
    color: white;
  `;
  icon.textContent = '⚠';
  
  const title = document.createElement('h2');
  title.style.cssText = `
    margin: 0 0 16px;
    color: #212121;
    font-size: 24px;
    text-align: center;
  `;
  title.textContent = result.riskLevel === 'critical' ? 
    'Critical Security Warning' : 'Security Warning';
  
  const description = document.createElement('p');
  description.style.cssText = `
    margin: 0 0 20px;
    color: #616161;
    font-size: 16px;
    line-height: 1.5;
    text-align: center;
  `;
  description.textContent = 'This page shows signs of being a potential scam or phishing attempt. We recommend caution before proceeding.';
  
  const findingsList = document.createElement('div');
  findingsList.style.cssText = `
    background: #F5F5F5;
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 24px;
    max-height: 200px;
    overflow-y: auto;
  `;
  
  const topFindings = result.findings.slice(0, 5);
  topFindings.forEach(finding => {
    const item = document.createElement('div');
    item.style.cssText = `
      padding: 8px 0;
      color: #424242;
      font-size: 14px;
      border-bottom: 1px solid #E0E0E0;
    `;
    item.textContent = `• ${finding.description}`;
    findingsList.appendChild(item);
  });
  
  const buttonContainer = document.createElement('div');
  buttonContainer.style.cssText = `
    display: flex;
    gap: 12px;
    justify-content: center;
  `;
  
  const closeButton = document.createElement('button');
  closeButton.style.cssText = `
    padding: 12px 32px;
    background: ${severityColor};
    color: white;
    border: none;
    border-radius: 6px;
    font-size: 16px;
    font-weight: 600;
    cursor: pointer;
  `;
  closeButton.textContent = 'Leave This Site';
  closeButton.onclick = () => {
    window.history.back();
  };
  
  const proceedButton = document.createElement('button');
  proceedButton.style.cssText = `
    padding: 12px 32px;
    background: transparent;
    color: #616161;
    border: 2px solid #BDBDBD;
    border-radius: 6px;
    font-size: 16px;
    font-weight: 600;
    cursor: pointer;
  `;
  proceedButton.textContent = 'Proceed Anyway';
  proceedButton.onclick = () => {
    overlay.remove();
  };
  
  buttonContainer.appendChild(closeButton);
  buttonContainer.appendChild(proceedButton);
  
  warningBox.appendChild(icon);
  warningBox.appendChild(title);
  warningBox.appendChild(description);
  warningBox.appendChild(findingsList);
  warningBox.appendChild(buttonContainer);
  
  overlay.appendChild(warningBox);
  document.body.appendChild(overlay);
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'analyzePageLoad') {
    collectPageData();
    performAnalysis();
  }
  
  if (request.action === 'showWarning') {
    displayWarningOverlay(request.data);
  }
});

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initialize);
} else {
  initialize();
}
