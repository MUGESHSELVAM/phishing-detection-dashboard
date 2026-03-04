// content script placeholder: could be used to block page or modify DOM

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'check_url') {
    // optionally display warning overlay
    // could also call backend API here
  }
});