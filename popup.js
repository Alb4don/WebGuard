let currentAnalysis = null;

document.addEventListener('DOMContentLoaded', () => {
  initializePopup();
  setupEventListeners();
});

async function initializePopup() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab || !tab.url) {
      showError();
      return;
    }
    
    if (tab.url.startsWith('chrome://') || 
        tab.url.startsWith('chrome-extension://') ||
        tab.url.startsWith('about:')) {
      showError('Cannot analyze internal browser pages');
      return;
    }
    
    await loadAnalysis(tab.url);
  } catch (error) {
    console.error('Initialization error:', error);
    showError();
  }
}

async function loadAnalysis(url) {
  showLoading();
  
  try {
    const history = await chrome.storage.local.get('analysisHistory');
    const cached = history.analysisHistory?.[url];
    
    if (cached && Date.now() - cached.timestamp < 300000) {
      displayResults(cached.result);
    } else {
      setTimeout(() => {
        chrome.storage.local.get('analysisHistory', (data) => {
          const updated = data.analysisHistory?.[url];
          if (updated) {
            displayResults(updated.result);
          } else {
            showError('Analysis in progress. Please wait...');
          }
        });
      }, 2000);
    }
  } catch (error) {
    console.error('Load error:', error);
    showError();
  }
}

function displayResults(analysis) {
  currentAnalysis = analysis;
  
  hideLoading();
  document.getElementById('results').style.display = 'block';
  
  const statusIcon = document.getElementById('status-icon');
  const statusTitle = document.getElementById('status-title');
  const statusDescription = document.getElementById('status-description');
  
  statusIcon.className = `status-icon ${analysis.riskLevel}`;
  
  const statusConfig = {
    'safe': {
      icon: '✓',
      title: 'Page Appears Safe',
      description: 'No significant security concerns detected on this page.'
    },
    'low': {
      icon: '✓',
      title: 'Low Risk Detected',
      description: 'Minor concerns found, but the page appears generally safe.'
    },
    'medium': {
      icon: '?',
      title: 'Medium Risk Detected',
      description: 'Some concerning patterns detected. Exercise caution.'
    },
    'high': {
      icon: '!',
      title: 'High Risk Warning',
      description: 'Multiple security concerns detected. We recommend leaving this page.'
    },
    'critical': {
      icon: '!',
      title: 'Critical Threat Detected',
      description: 'This page shows strong indicators of being a scam. Leave immediately.'
    }
  };
  
  const config = statusConfig[analysis.riskLevel] || statusConfig['safe'];
  statusIcon.textContent = config.icon;
  statusTitle.textContent = config.title;
  statusDescription.textContent = config.description;
  
  const scoreFill = document.getElementById('score-fill');
  const scoreText = document.getElementById('score-text');
  
  const scorePercentage = 100 - analysis.score;
  scoreFill.style.width = `${scorePercentage}%`;
  scoreText.textContent = `${scorePercentage}/100`;
  
  const scoreColors = {
    'safe': '#4CAF50',
    'low': '#66BB6A',
    'medium': '#FFA000',
    'high': '#F57C00',
    'critical': '#D32F2F'
  };
  scoreFill.style.backgroundColor = scoreColors[analysis.riskLevel];
  
  if (analysis.findings && analysis.findings.length > 0) {
    displayFindings(analysis.findings);
  }
}

function displayFindings(findings) {
  const findingsSection = document.getElementById('findings-section');
  const findingsList = document.getElementById('findings-list');
  
  findingsSection.style.display = 'block';
  findingsList.innerHTML = '';
  
  const topFindings = findings.slice(0, 3);
  
  topFindings.forEach(finding => {
    const item = document.createElement('div');
    item.className = 'finding-item';
    
    if (finding.severity >= 9) {
      item.classList.add('severity-critical');
    } else if (finding.severity >= 7) {
      item.classList.add('severity-high');
    } else if (finding.severity >= 5) {
      item.classList.add('severity-medium');
    } else {
      item.classList.add('severity-low');
    }
    
    const text = document.createElement('div');
    text.className = 'finding-text';
    text.textContent = finding.description;
    
    item.appendChild(text);
    findingsList.appendChild(item);
  });
}

function setupEventListeners() {
  document.getElementById('refresh-btn')?.addEventListener('click', async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
      chrome.storage.local.get('analysisHistory', (data) => {
        const history = data.analysisHistory || {};
        delete history[tab.url];
        chrome.storage.local.set({ analysisHistory: history }, () => {
          chrome.tabs.sendMessage(tab.id, { action: 'analyzePageLoad', url: tab.url })
            .catch(() => {});
          setTimeout(() => loadAnalysis(tab.url), 1000);
        });
      });
    }
  });
  
  document.getElementById('details-btn')?.addEventListener('click', () => {
    if (currentAnalysis) {
      showDetailsModal(currentAnalysis);
    }
  });
  
  document.getElementById('close-modal')?.addEventListener('click', () => {
    hideDetailsModal();
  });
  
  document.getElementById('settings-btn')?.addEventListener('click', () => {
    chrome.runtime.openOptionsPage();
  });
  
  document.getElementById('history-btn')?.addEventListener('click', () => {
    showHistoryView();
  });
}

function showDetailsModal(analysis) {
  const modal = document.getElementById('details-modal');
  const modalBody = document.getElementById('modal-body');
  
  modalBody.innerHTML = '';
  
  const scoreSection = createDetailSection('Overall Assessment', [
    `Risk Level: ${analysis.riskLevel.toUpperCase()}`,
    `Security Score: ${100 - analysis.score}/100`,
    `Analysis Time: ${new Date(analysis.timestamp).toLocaleString()}`
  ]);
  modalBody.appendChild(scoreSection);
  
  if (analysis.findings && analysis.findings.length > 0) {
    const findingsSection = document.createElement('div');
    findingsSection.className = 'detail-section';
    
    const title = document.createElement('h3');
    title.textContent = 'All Detected Issues';
    findingsSection.appendChild(title);
    
    const list = document.createElement('ul');
    list.className = 'detail-list';
    
    analysis.findings.forEach(finding => {
      const item = document.createElement('li');
      item.textContent = `[Severity ${finding.severity}/10] ${finding.description}`;
      list.appendChild(item);
    });
    
    findingsSection.appendChild(list);
    modalBody.appendChild(findingsSection);
  }
  
  modal.style.display = 'flex';
}

function createDetailSection(title, items) {
  const section = document.createElement('div');
  section.className = 'detail-section';
  
  const heading = document.createElement('h3');
  heading.textContent = title;
  section.appendChild(heading);
  
  const list = document.createElement('ul');
  list.className = 'detail-list';
  
  items.forEach(item => {
    const li = document.createElement('li');
    li.textContent = item;
    list.appendChild(li);
  });
  
  section.appendChild(list);
  return section;
}

function hideDetailsModal() {
  document.getElementById('details-modal').style.display = 'none';
}

function showHistoryView() {
  chrome.storage.local.get('analysisHistory', (data) => {
    const history = data.analysisHistory || {};
    const entries = Object.entries(history)
      .sort((a, b) => b[1].timestamp - a[1].timestamp)
      .slice(0, 10);
    
    const modal = document.getElementById('details-modal');
    const modalBody = document.getElementById('modal-body');
    
    modalBody.innerHTML = '';
    
    const title = document.createElement('h3');
    title.textContent = 'Recent Analysis History';
    title.style.marginBottom = '16px';
    modalBody.appendChild(title);
    
    if (entries.length === 0) {
      const empty = document.createElement('p');
      empty.textContent = 'No analysis history available.';
      empty.style.color = '#757575';
      modalBody.appendChild(empty);
    } else {
      entries.forEach(([url, data]) => {
        const item = document.createElement('div');
        item.style.padding = '12px';
        item.style.marginBottom = '8px';
        item.style.background = '#FAFAFA';
        item.style.borderRadius = '8px';
        item.style.cursor = 'pointer';
        
        const urlText = document.createElement('div');
        urlText.textContent = new URL(url).hostname;
        urlText.style.fontWeight = '600';
        urlText.style.marginBottom = '4px';
        
        const riskText = document.createElement('div');
        riskText.textContent = `Risk: ${data.result.riskLevel.toUpperCase()}`;
        riskText.style.fontSize = '12px';
        riskText.style.color = '#757575';
        
        item.appendChild(urlText);
        item.appendChild(riskText);
        
        item.addEventListener('click', () => {
          hideDetailsModal();
        });
        
        modalBody.appendChild(item);
      });
    }
    
    modal.style.display = 'flex';
  });
}

function showLoading() {
  document.getElementById('loading').style.display = 'flex';
  document.getElementById('results').style.display = 'none';
  document.getElementById('error').style.display = 'none';
}

function hideLoading() {
  document.getElementById('loading').style.display = 'none';
}

function showError(message = 'Unable to analyze this page') {
  hideLoading();
  const errorDiv = document.getElementById('error');
  errorDiv.querySelector('p').textContent = message;
  errorDiv.style.display = 'flex';
}
