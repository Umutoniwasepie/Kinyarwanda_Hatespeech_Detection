let selectedText = '';

document.addEventListener('mouseup', function() {
  selectedText = window.getSelection().toString().trim();
});

document.addEventListener('keyup', function() {
  selectedText = window.getSelection().toString().trim();
});

chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
  if (request.action === 'getSelectedText') {
    sendResponse({text: selectedText});
  }
});