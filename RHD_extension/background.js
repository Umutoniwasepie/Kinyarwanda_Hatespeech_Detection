chrome.runtime.onInstalled.addListener(() => {
  console.log('Kinyarwanda Hate Speech Detector installed');
});

chrome.action.onClicked.addListener((tab) => {
  chrome.scripting.executeScript({
    target: {tabId: tab.id},
    function: () => {
      console.log('Extension clicked');
    }
  });
});