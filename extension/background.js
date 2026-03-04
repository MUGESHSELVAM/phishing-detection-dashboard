// background service worker listens for tab updates and can perform checks

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    // send message to content script or directly call API
    chrome.tabs.sendMessage(tabId, {action: 'check_url', url: tab.url});
  }
});