class RiskAnalyzer {
  constructor() {
    this.suspiciousKeywords = null;
    this.scamPatterns = null;
    this.initialized = false;
  }

  async initialize() {
    if (this.initialized) return;

    try {
      // Chargement des données de détection
      const [keywordsResponse, patternsResponse] = await Promise.all([
        fetch(chrome.runtime.getURL('data/suspicious-keywords.json')),
        fetch(chrome.runtime.getURL('data/scam-patterns.json'))
      ]);

      this.suspiciousKeywords = await keywordsResponse.json();
      this.scamPatterns = await patternsResponse.json();
      this.initialized = true;

      console.log('RiskAnalyzer initialized successfully');
    } catch (error) {
      console.error('Failed to initialize RiskAnalyzer:', error);
      throw error;
    }
  }

  /**
   * Analyse complète d'une annonce
   * @param {Object} adData - Données de l'annonce
   * @returns {Object} Résultat de l'analyse avec score et détails
   */
  async analyzeAd(adData) {
    if (!this.initialized) {
      await this.initialize();
    }

    const analysis = {
      riskScore: 0,
      riskLevel: 'low',
      detectedThreats: [],
      recommendations: [],
      timestamp: Date.now()
    };

    // Analyses multiples
    const textAnalysis = this.analyzeText(adData.title, adData.description);
    const priceAnalysis = this.analyzePrice(adData.price, adData.category);
    const sellerAnalysis = this.analyzeSeller(adData.seller);
    const behaviorAnalysis = this.analyzeBehavior(adData);
    const patternAnalysis = this.analyzePatterns(adData);

    // Fusion des résultats
    analysis.riskScore = this.calculateFinalScore([
      textAnalysis,
      priceAnalysis,
      sellerAnalysis,
      behaviorAnalysis,
      patternAnalysis
    ]);

    analysis.detectedThreats = this.consolidateThreats([
      textAnalysis,
      priceAnalysis,
      sellerAnalysis,
      behaviorAnalysis,
      patternAnalysis
    ]);

    analysis.riskLevel = this.determineRiskLevel(analysis.riskScore);
    analysis.recommendations = this.generateRecommendations(analysis);

    return analysis;
  }

  /**
   * Analyse du texte (titre + description)
   */
  analyzeText(title, description) {
    const fullText = `${title} ${description}`.toLowerCase();
    const threats = [];
    let score = 0;

    // Vérification des mots-clés suspects
    Object.entries(this.suspiciousKeywords).forEach(([category, keywords]) => {
      Object.entries(keywords).forEach(([riskLevel, wordList]) => {
        wordList.forEach(keyword => {
          if (fullText.includes(keyword.toLowerCase())) {
            const weight = this.getRiskWeight(riskLevel);
            score += weight;
            threats.push({
              type: 'keyword',
              category,
              keyword,
              riskLevel,
              weight
            });
          }
        });
      });
    });

    return { score, threats, type: 'text' };
  }

  /**
   * Analyse des prix suspects
   */
  analyzePrice(price, category) {
    const threats = [];
    let score = 0;

    if (!price || price <= 0) {
      return { score: 0, threats, type: 'price' };
    }

    // Prix psychologique suspect
    if (price % 100 === 0 && price > 200) {
      score += 10;
      threats.push({
        type: 'price_pattern',
        reason: 'Prix rond suspect pour objet de valeur',
        riskLevel: 'low'
      });
    }

    // Prix se terminant par 99 ou 95 (inhabituel sur LeBonCoin)
    if (price % 100 === 99 || price % 100 === 95) {
      score += 5;
      threats.push({
        type: 'price_pattern',
        reason: 'Prix psychologique inhabituel sur LeBonCoin',
        riskLevel: 'low'
      });
    }

    // Prix anormalement bas (simulation - nécessiterait une base de données de prix)
    if (this.isPriceSuspiciouslyLow(price, category)) {
      score += 50;
      threats.push({
        type: 'price_too_low',
        reason: 'Prix anormalement bas pour cette catégorie',
        riskLevel: 'high'
      });
    }

    return { score, threats, type: 'price' };
  }

  /**
   * Analyse du profil vendeur
   */
  analyzeSeller(sellerData) {
    const threats = [];
    let score = 0;

    if (!sellerData) {
      return { score: 0, threats, type: 'seller' };
    }

    // Compte récent
    if (sellerData.accountAge && sellerData.accountAge < 30) {
      score += 20;
      threats.push({
        type: 'new_account',
        reason: 'Compte créé récemment',
        riskLevel: 'medium'
      });
    }

    // Pas d'avis
    if (sellerData.reviewCount === 0) {
      score += 15;
      threats.push({
        type: 'no_reviews',
        reason: 'Aucun avis sur le vendeur',
        riskLevel: 'medium'
      });
    }

    // Nombre suspect d'objets similaires
    if (sellerData.similarItemsCount > 5) {
      score += 30;
      threats.push({
        type: 'multiple_items',
        reason: 'Vendeur avec beaucoup d\'objets identiques',
        riskLevel: 'high'
      });
    }

    return { score, threats, type: 'seller' };
  }

  /**
   * Analyse comportementale
   */
  analyzeBehavior(adData) {
    const threats = [];
    let score = 0;

    // Une seule photo
    if (adData.photosCount === 1) {
      score += 15;
      threats.push({
        type: 'single_photo',
        reason: 'Une seule photo fournie',
        riskLevel: 'medium'
      });
    }

    // Localisation vague
    if (this.isLocationVague(adData.location)) {
      score += 20;
      threats.push({
        type: 'vague_location',
        reason: 'Localisation volontairement vague',
        riskLevel: 'medium'
      });
    }

    return { score, threats, type: 'behavior' };
  }

  /**
   * Analyse des patterns regex
   */
  analyzePatterns(adData) {
    const threats = [];
    let score = 0;
    const fullText = `${adData.title} ${adData.description}`.toLowerCase();

    // Application des patterns textuels
    Object.entries(this.scamPatterns.text_patterns).forEach(([patternName, patternData]) => {
      const regex = new RegExp(patternData.pattern, 'gi');
      const matches = fullText.match(regex);

      if (matches) {
        const weight = this.getRiskWeight(patternData.risk_level);
        score += weight * matches.length;
        threats.push({
          type: 'pattern_match',
          pattern: patternName,
          matches: matches.length,
          riskLevel: patternData.risk_level,
          description: patternData.description
        });
      }
    });

    return { score, threats, type: 'pattern' };
  }

  /**
   * Calcul du score final pondéré
   */
  calculateFinalScore(analyses) {
    const weights = {
      text: 0.25,
      price: 0.2,
      seller: 0.2,
      behavior: 0.15,
      pattern: 0.2
    };

    return analyses.reduce((total, analysis) => {
      const weight = weights[analysis.type] || 0.1;
      return total + (analysis.score * weight);
    }, 0);
  }

  /**
   * Consolidation des menaces détectées
   */
  consolidateThreats(analyses) {
    const allThreats = analyses.flatMap(analysis => analysis.threats);
    
    // Dédoublonnage et tri par niveau de risque
    const uniqueThreats = allThreats.filter((threat, index, self) => 
      index === self.findIndex(t => t.type === threat.type && t.reason === threat.reason)
    );

    return uniqueThreats.sort((a, b) => {
      const riskOrder = { high: 3, medium: 2, low: 1 };
      return riskOrder[b.riskLevel] - riskOrder[a.riskLevel];
    });
  }

  /**
   * Détermination du niveau de risque global
   */
  determineRiskLevel(score) {
    if (score >= 60) return 'high';
    if (score >= 30) return 'medium';
    return 'low';
  }

  /**
   * Génération de recommandations
   */
  generateRecommendations(analysis) {
    const recommendations = [];

    if (analysis.riskLevel === 'high') {
      recommendations.push('⚠️ ATTENTION : Cette annonce présente plusieurs signaux d\'alarme');
      recommendations.push('❌ Évitez cette annonce ou soyez extrêmement prudent');
      recommendations.push('🔍 Vérifiez l\'identité du vendeur avant tout contact');
    } else if (analysis.riskLevel === 'medium') {
      recommendations.push('⚡ Prudence recommandée pour cette annonce');
      recommendations.push('🤝 Privilégiez la remise en main propre');
      recommendations.push('💳 Évitez les paiements avant rencontre');
    } else {
      recommendations.push('✅ Annonce qui semble normale');
      recommendations.push('🛡️ Respectez les bonnes pratiques de sécurité');
    }

    return recommendations;
  }

  /**
   * Utilitaires
   */
  getRiskWeight(riskLevel) {
    const weights = { low: 5, medium: 15, high: 30 };
    return weights[riskLevel] || 5;
  }

  isPriceSuspiciouslyLow(price, category) {
    // Simulation simple - dans la vraie vie, vous auriez une base de données de prix
    const suspiciousThresholds = {
      'informatique': 50,
      'telephonie': 30,
      'electromenager': 20,
      'vehicules': 500
    };

    return price < (suspiciousThresholds[category] || 10);
  }

  isLocationVague(location) {
    if (!location) return true;
    
    const vagueTerms = ['région', 'proche', 'alentours', 'secteur', 'environ'];
    return vagueTerms.some(term => location.toLowerCase().includes(term));
  }
}

// Export pour utilisation dans d'autres modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = RiskAnalyzer;
} else {
  window.RiskAnalyzer = RiskAnalyzer;
}