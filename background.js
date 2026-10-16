"use strict";

/**
 * CyberGuard MVP - background.js (service worker, Manifest V3)
 * Gerenciamento de estado básico. Não contém lógica de análise:
 * toda a inteligência fica no backend Python.
 */

const DEFAULT_STATE = {
  installedAt: null,
  preferredMode: "amador",
  lastAnalyzedUrl: null,
};

chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === "install") {
    const state = { ...DEFAULT_STATE, installedAt: new Date().toISOString() };
    await chrome.storage.local.set(state);
    console.log("[CyberGuard] Extensão instalada. Estado inicial criado.");
  }
});

// Permite que o popup registre a última URL analisada (uso opcional/futuro).
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "SET_LAST_ANALYZED_URL" && typeof message.url === "string") {
    chrome.storage.local.set({ lastAnalyzedUrl: message.url }).then(() => {
      sendResponse({ ok: true });
    });
    return true; // resposta assíncrona
  }
  return false;
});
