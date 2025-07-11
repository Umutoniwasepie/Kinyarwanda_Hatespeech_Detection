const API_URL = 'http://127.0.0.1:5000/api/analyze/public';
const PROD_URL = 'https://kinyarwanda-hatespeech-detection.onrender.com/api/analyze/public';

document.addEventListener('DOMContentLoaded', function() {
  const analyzeBtn = document.getElementById('analyzeBtn');
  const resultDiv = document.getElementById('result');

  analyzeBtn.addEventListener('click', analyzeText);

  function analyzeText() {
    analyzeBtn.disabled = true;
    resultDiv.innerHTML = '<div class="loading">Analyzing...</div>';

    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
      chrome.scripting.executeScript({
        target: {tabId: tabs[0].id},
        function: getSelectedText
      }, function(results) {
        if (results && results[0] && results[0].result) {
          const selectedText = results[0].result;
          
          if (!selectedText.trim()) {
            resultDiv.innerHTML = '<div class="warning">Please select some text on the page first</div>';
            analyzeBtn.disabled = false;
            return;
          }

          sendToAPI(selectedText);
        } else {
          resultDiv.innerHTML = '<div class="error">Could not get selected text</div>';
          analyzeBtn.disabled = false;
        }
      });
    });
  }

  function sendToAPI(text) {
    const urls = [API_URL, PROD_URL];
    
    tryURL(urls, 0, text);
  }

  function tryURL(urls, index, text) {
    if (index >= urls.length) {
      resultDiv.innerHTML = '<div class="error">Could not connect to analysis service</div>';
      analyzeBtn.disabled = false;
      return;
    }

    fetch(urls[index], {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({text: text})
    })
    .then(response => {
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      return response.json();
    })
    .then(data => {
      displayResult(data, text);
      analyzeBtn.disabled = false;
    })
    .catch(error => {
      console.log(`Failed with URL ${urls[index]}: ${error.message}`);
      tryURL(urls, index + 1, text);
    });
  }

  function displayResult(data, originalText) {
    if (data.error) {
      resultDiv.innerHTML = `<div class="error">${data.error}</div>`;
      return;
    }

    const prediction = data.prediction;
    const explanation = data.explanation || [];
    
    let statusClass = 'safe';
    let statusText = 'Safe Content';
    
    if (prediction === 'hate' || prediction === 'offensive') {
      statusClass = 'flagged';
      statusText = prediction === 'hate' ? 'Hate Speech Detected' : 'Offensive Content Detected';
    }

    let resultHTML = `
      <div class="result-content">
        <strong>Analysis Result:</strong>
        <span class="${statusClass}">${statusText}</span>
    `;

    if (explanation.length > 0) {
      resultHTML += `
        <div class="top-words">
          <strong>Key words:</strong> ${explanation.join(', ')}
        </div>
      `;
    }

    resultHTML += '</div>';
    resultDiv.innerHTML = resultHTML;
  }
});

function getSelectedText() {
  return window.getSelection().toString();
}