/**
 * Analyseur de texte pour la détection d'arnaques
 */
class TextAnalyzer {
  constructor() {
    this.frenchStopWords = [
      'le', 'de', 'et', 'à', 'un', 'il', 'être', 'et', 'en', 'avoir', 'que', 'pour',
      'dans', 'ce', 'son', 'une', 'sur', 'avec', 'ne', 'se', 'pas', 'tout', 'plus',
      'par', 'grand', 'en', 'une', 'pour', 'que', 'les', 'des', 'est', 'du', 'la'
    ];
  }

  /**
   * Analyse complète d'un texte
   */
  analyzeText(text) {
    if (!text || typeof text !== 'string') {
      return this.getEmptyAnalysis();
    }

    const cleanText = this.preprocessText(text);
    
    return {
      originalText: text,
      cleanText: cleanText,
      length: text.length,
      wordCount: this.countWords(cleanText),
      sentences: this.getSentences(text),
      urgencyScore: this.calculateUrgencyScore(text),
      emotionalScore: this.calculateEmotionalScore(text),
      suspiciousPatterns: this.detectSuspiciousPatterns(text),
      readabilityScore: this.calculateReadabilityScore(cleanText),
      languageQuality: this.assessLanguageQuality(text),
      contactAttempts: this.detectContactAttempts(text),
      priceKeywords: this.extractPriceKeywords(text),
      locationKeywords: this.extractLocationKeywords(text)
    };
  }

  /**
   * Préprocessing du texte
   */
  preprocessText(text) {
    return text
      .toLowerCase()
      .replace(/[^\w\s]/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
  }

  /**
   * Comptage des mots
   */
  countWords(text) {
    const words = text.split(/\s+/).filter(word => 
      word.length > 1 && !this.frenchStopWords.includes(word)
    );
    return words.length;
  }

  /**
   * Extraction des phrases
   */
  getSentences(text) {
    const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 0);
    return {
      count: sentences.length,
      avgLength: sentences.reduce((sum, s) => sum + s.length, 0) / sentences.length || 0,
      sentences: sentences.map(s => s.trim())
    };
  }

  /**
   * Calcul du score d'urgence
   */
  calculateUrgencyScore(text) {
    const urgencyIndicators = [
      { pattern: /urgent[e]?/gi, weight: 3 },
      { pattern: /rapidement/gi, weight: 2 },
      { pattern: /vite/gi, weight: 2 },
      { pattern: /immédiatement/gi, weight: 3 },
      { pattern: /tout de suite/gi, weight: 2 },
      { pattern: /départ demain/gi, weight: 4 },
      { pattern: /partir ce soir/gi, weight: 4 },
      { pattern: /fin de semaine/gi, weight: 2 },
      { pattern: /déménagement/gi, weight: 1 },
      { pattern: /liquidation/gi, weight: 3 },
      { pattern: /braderie/gi, weight: 2 },
      { pattern: /!{2,}/g, weight: 1 } // Multiples exclamations
    ];

    let score = 0;
    const matches = [];

    urgencyIndicators.forEach(indicator => {
      const found = text.match(indicator.pattern);
      if (found) {
        score += indicator.weight * found.length;
        matches.push({
          pattern: indicator.pattern.source,
          matches: found.length,
          weight: indicator.weight
        });
      }
    });

    return { score, matches };
  }

  /**
   * Calcul du score émotionnel
   */
  calculateEmotionalScore(text) {
    const emotionalIndicators = [
      { pattern: /maladie/gi, weight: 3 },
      { pattern: /décès/gi, weight: 4 },
      { pattern: /divorce/gi, weight: 3 },
      { pattern: /difficultés financières/gi, weight: 4 },
      { pattern: /au chômage/gi, weight: 3 },
      { pattern: /pour ma fille/gi, weight: 2 },
      { pattern: /pour mon fils/gi, weight: 2 },
      { pattern: /cadeau/gi, weight: 1 },
      { pattern: /anniversaire/gi, weight: 1 },
      { pattern: /surprise/gi, weight: 2 },
      { pattern: /personne âgée/gi, weight: 3 },
      { pattern: /handicapé/gi, weight: 3 },
      { pattern: /hôpital/gi, weight: 3 }
    ];

    let score = 0;
    const matches = [];

    emotionalIndicators.forEach(indicator => {
      const found = text.match(indicator.pattern);
      if (found) {
        score += indicator.weight * found.length;
        matches.push({
          pattern: indicator.pattern.source,
          matches: found.length,
          weight: indicator.weight
        });
      }
    });

    return { score, matches };
  }

  /**
   * Détection de patterns suspects
   */
  detectSuspiciousPatterns(text) {
    const patterns = [
      {
        name: 'phone_in_text',
        pattern: /0[1-9](?:[0-9]{8})/g,
        description: 'Numéro de téléphone dans le texte',
        risk: 'high'
      },
      {
        name: 'email_in_text',
        pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
        description: 'Email dans le texte',
        risk: 'high'
      },
      {
        name: 'foreign_phone',
        pattern: /\+(?!33)[0-9]{10,15}/g,
        description: 'Numéro étranger',
        risk: 'high'
      },
      {
        name: 'external_platform',
        pattern: /(facebook|instagram|whatsapp|telegram|signal|viber)/gi,
        description: 'Mention d\'autres plateformes',
        risk: 'medium'
      },
      {
        name: 'payment_methods',
        pattern: /(western union|moneygram|paypal famille|bitcoin|crypto)/gi,
        description: 'Méthodes de paiement suspectes',
        risk: 'high'
      },
      {
        name: 'shipping_only',
        pattern: /(expédition uniquement|envoi seulement|pas de remise)/gi,
        description: 'Expédition uniquement',
        risk: 'medium'
      },
      {
        name: 'price_justification',
        pattern: /(prix sacrifié|bradé|liquidation|perte financière)/gi,
        description: 'Justification de prix bas',
        risk: 'medium'
      },
      {
        name: 'authenticity_claims',
        pattern: /(100% authentique|garantie authenticité|certificat)/gi,
        description: 'Revendications d\'authenticité',
        risk: 'low'
      },
      {
        name: 'repeated_chars',
        pattern: /([a-zA-Z])\1{3,}/g,
        description: 'Caractères répétés',
        risk: 'low'
      },
      {
        name: 'excessive_caps',
        pattern: /[A-Z]{5,}/g,
        description: 'Majuscules excessives',
        risk: 'low'
      }
    ];

    const detected = [];

    patterns.forEach(pattern => {
      const matches = text.match(pattern.pattern);
      if (matches) {
        detected.push({
          name: pattern.name,
          description: pattern.description,
          risk: pattern.risk,
          matches: matches,
          count: matches.length
        });
      }
    });

    return detected;
  }

  /**
   * Calcul de la lisibilité
   */
  calculateReadabilityScore(text) {
    const words = text.split(/\s+/).length;
    const sentences = text.split(/[.!?]+/).length;
    const avgWordsPerSentence = words / sentences || 0;
    
    // Score basé sur la complexité (plus c'est simple, mieux c'est)
    let score = 100;
    
    // Pénalité pour phrases trop longues
    if (avgWordsPerSentence > 20) score -= 20;
    else if (avgWordsPerSentence > 15) score -= 10;
    
    // Pénalité pour texte trop court (suspect)
    if (words < 10) score -= 30;
    
    // Pénalité pour manque de ponctuation
    const punctuationCount = (text.match(/[.!?]/g) || []).length;
    if (punctuationCount === 0 && words > 20) score -= 15;

    return Math.max(0, Math.min(100, score));
  }

  /**
   * Évaluation de la qualité linguistique
   */
  assessLanguageQuality(text) {
    const issues = [];
    let score = 100;

    // Vérification des fautes courantes
    const commonMistakes = [
      { pattern: /sa va/gi, issue: 'Faute: "sa va" au lieu de "ça va"' },
      { pattern: /ces/gi, issue: 'Usage potentiellement incorrect de "ces"' },
      { pattern: /à/gi, issue: 'Vérifier l\'usage de "à"' },
      { pattern: /ou/gi, issue: 'Vérifier "ou" vs "où"' }
    ];

    // Détection de répétitions excessives
    const words = text.toLowerCase().split(/\s+/);
    const wordCount = {};
    words.forEach(word => {
      if (word.length > 3) {
        wordCount[word] = (wordCount[word] || 0) + 1;
      }
    });

    Object.entries(wordCount).forEach(([word, count]) => {
      if (count > 3) {
        score -= 5;
        issues.push(`Répétition excessive: "${word}" (${count} fois)`);
      }
    });

    // Vérification de l'absence de voyelles (copier-coller suspect)
    const vowels = text.match(/[aeiouAEIOU]/g) || [];
    const vowelRatio = vowels.length / text.length;
    if (vowelRatio < 0.2) {
      score -= 20;
      issues.push('Ratio de voyelles anormalement bas');
    }

    return {
      score: Math.max(0, score),
      issues: issues
    };
  }

  /**
   * Détection des tentatives de contact
   */
  detectContactAttempts(text) {
    const contactPatterns = [
      { type: 'phone', pattern: /(?:tel|téléphone|appel|appelle)/gi },
      { type: 'sms', pattern: /(?:sms|texto|message)/gi },
      { type: 'email', pattern: /(?:mail|email|e-mail)/gi },
      { type: 'social', pattern: /(?:facebook|instagram|snap)/gi },
      { type: 'messaging', pattern: /(?:whatsapp|telegram|signal)/gi }
    ];

    const detected = [];

    contactPatterns.forEach(pattern => {
      const matches = text.match(pattern.pattern);
      if (matches) {
        detected.push({
          type: pattern.type,
          count: matches.length,
          matches: matches
        });
      }
    });

    return detected;
  }

  /**
   * Extraction des mots-clés de prix
   */
  extractPriceKeywords(text) {
    const priceKeywords = [
      'négociable', 'débattable', 'ferme', 'fixe', 'bradé', 'sacrifié',
      'liquidation', 'affaire', 'occasion', 'bon prix', 'pas cher',
      'gratuit', 'offert', 'cadeau', 'bonus'
    ];

    const found = [];
    priceKeywords.forEach(keyword => {
      const regex = new RegExp(keyword, 'gi');
      const matches = text.match(regex);
      if (matches) {
        found.push({
          keyword: keyword,
          count: matches.length
        });
      }
    });

    return found;
  }

  /**
   * Extraction des mots-clés de localisation
   */
  extractLocationKeywords(text) {
    const locationKeywords = [
      'région', 'secteur', 'alentours', 'environ', 'proche', 'loin',
      'déplacement', 'livraison', 'expédition', 'envoi', 'poste',
      'remise', 'rdv', 'rendez-vous'
    ];

    const found = [];
    locationKeywords.forEach(keyword => {
      const regex = new RegExp(keyword, 'gi');
      const matches = text.match(regex);
      if (matches) {
        found.push({
          keyword: keyword,
          count: matches.length
        });
      }
    });

    return found;
  }

  /**
   * Analyse vide par défaut
   */
  getEmptyAnalysis() {
    return {
      originalText: '',
      cleanText: '',
      length: 0,
      wordCount: 0,
      sentences: { count: 0, avgLength: 0, sentences: [] },
      urgencyScore: { score: 0, matches: [] },
      emotionalScore: { score: 0, matches: [] },
      suspiciousPatterns: [],
      readabilityScore: 0,
      languageQuality: { score: 0, issues: [] },
      contactAttempts: [],
      priceKeywords: [],
      locationKeywords: []
    };
  }

  /**
   * Calcul d'un score de risque global pour le texte
   */
  calculateOverallRisk(analysis) {
    let riskScore = 0;

    // Poids des différents facteurs
    riskScore += analysis.urgencyScore.score * 2;
    riskScore += analysis.emotionalScore.score * 1.5;
    
    // Patterns suspects
    analysis.suspiciousPatterns.forEach(pattern => {
      const weights = { high: 10, medium: 5, low: 2 };
      riskScore += weights[pattern.risk] * pattern.count;
    });

    // Qualité linguistique (inversement proportionnelle)
    riskScore += (100 - analysis.languageQuality.score) * 0.3;

    // Tentatives de contact
    riskScore += analysis.contactAttempts.length * 5;

    return Math.min(100, riskScore);
  }
}

// Export pour utilisation
if (typeof module !== 'undefined' && module.exports) {
  module.exports = TextAnalyzer;
} else {
  window.TextAnalyzer = TextAnalyzer;
}