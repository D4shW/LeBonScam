/**
 * Script principal LeBonScam - Orchestrateur des fonctionnalités
 */

class LeBonScamContent {
  constructor() {
    this.riskAnalyzer = null;
    this.visualIndicator = null;
    this.realtimeMonitor = null;
    this.throttleManager = null;
    this.initialized = false;
    this.processedAds = new Set();
    this.observerActive = false;
  }

  /**
   * Initialisation de l'extension
   */
  async initialize() {
    if (this.initialized) return;

    try {
      console.log('🔍 LeBonScam: Initialisation en cours...');

      // Vérification que nous sommes sur LeBonCoin
      if (!this.isLeBonCoinPage()) {
        console.log('❌ LeBonScam: Page non-LeBonCoin détectée');
        return;
      }

      // Initialisation des composants
      this.riskAnalyzer = new RiskAnalyzer();
      this.visualIndicator = new VisualIndicator();
      this.realtimeMonitor = new RealTimeMonitor();
      this.throttleManager = new ThrottleManager();

      await this.riskAnalyzer.initialize();
      
      this.initialized = true;
      console.log('✅ LeBonScam: Initialisation terminée');

      // Démarrage des analyses
      await this.startAnalysis();

    } catch (error) {
      console.error('❌ LeBonScam: Erreur d\'initialisation:', error);
    }
  }

  /**
   * Vérification que nous sommes sur LeBonCoin
   */
  isLeBonCoinPage() {
    return window.location.hostname === 'www.leboncoin.fr';
  }

  /**
   * Démarrage des analyses
   */
  async startAnalysis() {
    // Analyse initiale des annonces déjà présentes
    await this.analyzeExistingAds();

    // Surveillance des nouvelles annonces (scroll infini, navigation)
    this.setupObserver();

    // Surveillance des changements de page
    this.setupNavigationListener();

    console.log('🔍 LeBonScam: Surveillance active');
  }

  /**
   * Analyse des annonces déjà présentes sur la page
   */
  async analyzeExistingAds() {
    const adElements = this.findAdElements();
    
    if (adElements.length === 0) {
      console.log('📭 LeBonScam: Aucune annonce détectée sur cette page');
      return;
    }

    console.log(`🔍 LeBonScam: Analyse de ${adElements.length} annonces...`);

    for (const adElement of adElements) {
      await this.processAdElement(adElement);
    }
  }

  /**
   * Recherche des éléments d'annonce sur la page
   */
  findAdElements() {
    const selectors = [
      '[data-test-id="ad-card"]',
      '[data-qa-id="aditem_container"]',
      '.styles_adCard__2YFvs',
      '.cardLink',
      '[data-testid="serp-ad-card"]'
    ];

    let adElements = [];
    
    for (const selector of selectors) {
      const elements = document.querySelectorAll(selector);
      if (elements.length > 0) {
        adElements = Array.from(elements);
        break;
      }
    }

    return adElements;
  }

  /**
   * Traitement d'un élément d'annonce
   */
  async processAdElement(adElement) {
    try {
      // Éviter le double traitement
      const adId = this.getAdId(adElement);
      if (this.processedAds.has(adId)) {
        return;
      }

      // Extraction des données de l'annonce
      const adData = this.extractAdData(adElement);
      if (!adData) {
        console.warn('⚠️ LeBonScam: Impossible d\'extraire les données d\'annonce');
        return;
      }

      // Analyse des risques
      const analysis = await this.riskAnalyzer.analyzeAd(adData);
      
      // Affichage des indicateurs visuels
      this.visualIndicator.displayRiskIndicator(adElement, analysis);

      // Logging pour debug
      if (analysis.riskLevel !== 'low') {
        console.log(`🚨 LeBonScam: Risque ${analysis.riskLevel} détecté:`, {
          title: adData.title,
          score: analysis.riskScore,
          threats: analysis.detectedThreats.length
        });
      }

      // Marquer comme traité
      this.processedAds.add(adId);

      // Gestion de la limitation de débit
      await this.throttleManager.waitIfNeeded();

    } catch (error) {
      console.error('❌ LeBonScam: Erreur lors du traitement d\'annonce:', error);
    }
  }

  /**
   * Extraction des données d'une annonce
   */
  extractAdData(adElement) {
    try {
      const data = {
        title: this.extractTitle(adElement),
        description: this.extractDescription(adElement),
        price: this.extractPrice(adElement),
        location: this.extractLocation(adElement),
        category: this.extractCategory(adElement),
        photosCount: this.extractPhotosCount(adElement),
        seller: this.extractSellerInfo(adElement),
        timestamp: Date.now()
      };

      // Validation des données minimales
      if (!data.title) {
        return null;
      }

      return data;
    } catch (error) {
      console.error('❌ LeBonScam: Erreur extraction données:', error);
      return null;
    }
  }

  /**
   * Extraction du titre
   */
  extractTitle(adElement) {
    const selectors = [
      '[data-qa-id="aditem_title"]',
      '.styles_adCard__title',
      'h2',
      '.cardTitle',
      '[data-testid="ad-title"]'
    ];

    return this.extractTextBySelectors(adElement, selectors);
  }

  /**
   * Extraction de la description
   */
  extractDescription(adElement) {
    const selectors = [
      '[data-qa-id="aditem_description"]',
      '.styles_adCard__description',
      '.cardDescription',
      '[data-testid="ad-description"]'
    ];

    return this.extractTextBySelectors(adElement, selectors) || '';
  }

  /**
   * Extraction du prix
   */
  extractPrice(adElement) {
    const selectors = [
      '[data-qa-id="aditem_price"]',
      '.styles_adCard__price',
      '.cardPrice',
      '[data-testid="ad-price"]'
    ];

    const priceText = this.extractTextBySelectors(adElement, selectors);
    if (!priceText) return null;

    // Extraction du nombre depuis le texte du prix
    const priceMatch = priceText.match(/(\d+(?:\s?\d+)*)/);
    if (priceMatch) {
      return parseInt(priceMatch[1].replace(/\s/g, ''));
    }

    return null;
  }

  /**
   * Extraction de la localisation
   */
  extractLocation(adElement) {
    const selectors = [
      '[data-qa-id="aditem_location"]',
      '.styles_adCard__location',
      '.cardLocation',
      '[data-testid="ad-location"]'
    ];

    return this.extractTextBySelectors(adElement, selectors);
  }

  /**
   * Extraction de la catégorie
   */
  extractCategory(adElement) {
    // Tentative d'extraction depuis l'URL ou les métadonnées
    const categoryFromUrl = this.getCategoryFromUrl();
    if (categoryFromUrl) return categoryFromUrl;

    // Extraction depuis l'élément
    const selectors = [
      '[data-qa-id="aditem_category"]',
      '.styles_adCard__category',
      '.cardCategory'
    ];

    return this.extractTextBySelectors(adElement, selectors) || 'unknown';
  }

  /**
   * Extraction du nombre de photos
   */
  extractPhotosCount(adElement) {
    const photoElements = adElement.querySelectorAll('img, [data-qa-id="aditem_image"]');
    return photoElements.length;
  }

  /**
   * Extraction des informations vendeur
   */
  extractSellerInfo(adElement) {
    return {
      name: this.extractTextBySelectors(adElement, ['[data-qa-id="aditem_seller"]']),
      reviewCount: 0, // Difficile à extraire sans page détaillée
      accountAge: null, // Idem
      similarItemsCount: 0 // Idem
    };
  }

  /**
   * Utilitaire d'extraction de texte par sélecteurs
   */
  extractTextBySelectors(element, selectors) {
    for (const selector of selectors) {
      const found = element.querySelector(selector);
      if (found) {
        return found.textContent.trim();
      }
    }
    return null;
  }

  /**
   * Génération d'un ID unique pour une annonce
   */
  getAdId(adElement) {
    // Tentative d'extraction d'un ID depuis les attributs
    const possibleIds = [
      adElement.getAttribute('data-ad-id'),
      adElement.getAttribute('data-test-id'),
      adElement.getAttribute('data-qa-id'),
      adElement.getAttribute('id')
    ];

    for (const id of possibleIds) {
      if (id) return id;
    }

    // Fallback: génération basée sur le contenu
    const title = this.extractTitle(adElement);
    const price = this.extractPrice(adElement);
    return `${title}_${price}`.replace(/[^a-zA-Z0-9]/g, '_');
  }

  /**
   * Extraction de catégorie depuis l'URL
   */
  getCategoryFromUrl() {
    const urlPath = window.location.pathname;
    const categoryMatch = urlPath.match(/\/([^\/]+)\//);
    return categoryMatch ? categoryMatch[1] : null;
  }

  /**
   * Configuration de l'observateur pour les nouvelles annonces
   */
  setupObserver() {
    if (this.observerActive) return;

    const observer = new MutationObserver(async (mutations) => {
      for (const mutation of mutations) {
        if (mutation.type === 'childList') {
          for (const node of mutation.addedNodes) {
            if (node.nodeType === Node.ELEMENT_NODE) {
              // Vérifier si c'est une nouvelle annonce
              const newAds = this.findAdElements().filter(ad => 
                !this.processedAds.has(this.getAdId(ad))
              );

              for (const newAd of newAds) {
                await this.processAdElement(newAd);
              }
            }
          }
        }
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true
    });

    this.observerActive = true;
  }

  /**
   * Écoute des changements de navigation
   */
  setupNavigationListener() {
    // Surveillance des changements d'URL (SPA)
    let currentUrl = window.location.href;
    
    setInterval(() => {
      if (window.location.href !== currentUrl) {
        currentUrl = window.location.href;
        this.onNavigationChange();
      }
    }, 1000);

    // Écoute des événements de navigation
    window.addEventListener('popstate', () => this.onNavigationChange());
  }

  /**
   * Gestion des changements de navigation
   */
  async onNavigationChange() {
    console.log('🔄 LeBonScam: Navigation détectée, relance de l\'analyse...');
    
    // Reset du cache des annonces traitées
    this.processedAds.clear();
    
    // Petit délai pour laisser le temps au contenu de se charger
    setTimeout(() => {
      this.analyzeExistingAds();
    }, 1000);
  }
}

// Initialisation automatique
const lebonscam = new LeBonScamContent();

// Démarrage quand le DOM est prêt
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => lebonscam.initialize());
} else {
  lebonscam.initialize();
}

// Export global pour debug
window.LeBonScam = lebonscam;