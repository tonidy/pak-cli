/**
 * Random Character and Password Generator
 */

import { RandomGenerator as IRandomGenerator } from '../types';

export class RandomGenerator implements IRandomGenerator {
  /**
   * Generate random characters based on a pattern
   */
  generateChars(length: number, pattern: string): string {
    // Convert pattern to character set
    const charset = this.expandPattern(pattern);
    
    if (charset.length === 0) {
      throw new Error('Invalid pattern: no characters available');
    }
    
    // Use crypto.getRandomValues for secure random generation
    const randomValues = new Uint32Array(length);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      crypto.getRandomValues(randomValues);
    } else {
      // Fallback for Node.js
      const nodeCrypto = require('crypto');
      const buffer = nodeCrypto.randomBytes(length * 4);
      for (let i = 0; i < length; i++) {
        randomValues[i] = buffer.readUInt32BE(i * 4);
      }
    }
    
    let result = '';
    for (let i = 0; i < length; i++) {
      const randomIndex = randomValues[i] % charset.length;
      result += charset[randomIndex];
    }
    
    return result;
  }

  /**
   * Generate a secure passphrase
   */
  generatePassphrase(length: number): string {
    const words = [
      'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract',
      'absurd', 'abuse', 'access', 'accident', 'account', 'accuse', 'achieve', 'acid',
      'acoustic', 'acquire', 'across', 'act', 'action', 'actor', 'actress', 'actual',
      'adapt', 'add', 'addict', 'address', 'adjust', 'admit', 'adult', 'advance',
      'advice', 'aerobic', 'affair', 'affect', 'afford', 'afraid', 'again', 'against',
      'age', 'agent', 'agree', 'ahead', 'aim', 'air', 'airport', 'aisle',
      'alarm', 'album', 'alcohol', 'alert', 'alien', 'all', 'alley', 'allow',
      'almost', 'alone', 'alpha', 'already', 'also', 'alter', 'always', 'amateur',
      'amazing', 'among', 'amount', 'amused', 'analyst', 'anchor', 'ancient', 'anger',
      'angle', 'angry', 'animal', 'ankle', 'announce', 'annual', 'another', 'answer',
      'antenna', 'antique', 'anxiety', 'any', 'apart', 'apology', 'appear', 'apple',
      'approve', 'april', 'arcade', 'arch', 'arctic', 'area', 'arena', 'argue',
      'arm', 'armed', 'armor', 'army', 'around', 'arrange', 'arrest', 'arrive',
      'arrow', 'art', 'article', 'artist', 'artwork', 'ask', 'aspect', 'assault',
      'asset', 'assist', 'assume', 'asthma', 'athlete', 'atom', 'attack', 'attend',
      'attitude', 'attract', 'auction', 'audit', 'august', 'aunt', 'author', 'auto',
      'autumn', 'average', 'avocado', 'avoid', 'awake', 'aware', 'away', 'awesome',
      'awful', 'awkward', 'axis', 'baby', 'bachelor', 'bacon', 'badge', 'bag',
      'balance', 'balcony', 'ball', 'bamboo', 'banana', 'banner', 'bar', 'barely',
      'bargain', 'barrel', 'base', 'basic', 'basket', 'battle', 'beach', 'bean',
      'beauty', 'because', 'become', 'beef', 'before', 'begin', 'behave', 'behind',
      'believe', 'below', 'belt', 'bench', 'benefit', 'best', 'betray', 'better',
      'between', 'beyond', 'bicycle', 'bid', 'bike', 'bind', 'biology', 'bird',
      'birth', 'bitter', 'black', 'blade', 'blame', 'blanket', 'blast', 'bleak',
      'bless', 'blind', 'blood', 'blossom', 'blow', 'blue', 'blur', 'blush',
      'board', 'boat', 'body', 'boil', 'bomb', 'bone', 'bonus', 'book',
      'boost', 'border', 'boring', 'borrow', 'boss', 'bottom', 'bounce', 'box',
      'boy', 'bracket', 'brain', 'brand', 'brass', 'brave', 'bread', 'breeze',
      'brick', 'bridge', 'brief', 'bright', 'bring', 'brisk', 'broccoli', 'broken',
      'bronze', 'broom', 'brother', 'brown', 'brush', 'bubble', 'buddy', 'budget',
      'buffalo', 'build', 'bulb', 'bulk', 'bullet', 'bundle', 'bunker', 'burden',
      'burger', 'burst', 'bus', 'business', 'busy', 'butter', 'buyer', 'buzz'
    ];
    
    const wordCount = Math.max(4, Math.min(12, Math.floor(length / 6))); // Estimate words needed
    const selectedWords = [];
    
    for (let i = 0; i < wordCount; i++) {
      const randomIndex = this.getSecureRandomInt(0, words.length - 1);
      selectedWords.push(words[randomIndex]);
    }
    
    return selectedWords.join('-');
  }

  /**
   * Generate a numeric PIN
   */
  generatePin(length: number): string {
    return this.generateChars(length, '0-9');
  }

  /**
   * Generate a hex string
   */
  generateHex(length: number): string {
    return this.generateChars(length, '0-9A-F');
  }

  /**
   * Generate a base64-like string
   */
  generateBase64(length: number): string {
    return this.generateChars(length, 'A-Za-z0-9+/');
  }

  /**
   * Expand a pattern string to a character set
   */
  private expandPattern(pattern: string): string {
    let charset = '';
    let i = 0;
    
    while (i < pattern.length) {
      const char = pattern[i];
      
      // Check for range (e.g., A-Z, a-z, 0-9)
      if (i + 2 < pattern.length && pattern[i + 1] === '-') {
        const start = char.charCodeAt(0);
        const end = pattern[i + 2].charCodeAt(0);
        
        if (start <= end) {
          for (let code = start; code <= end; code++) {
            charset += String.fromCharCode(code);
          }
        }
        i += 3;
      } else {
        charset += char;
        i++;
      }
    }
    
    // Remove duplicates
    return [...new Set(charset)].join('');
  }

  /**
   * Get a secure random integer between min and max (inclusive)
   */
  private getSecureRandomInt(min: number, max: number): number {
    const range = max - min + 1;
    const maxValidValue = Math.floor(0xFFFFFFFF / range) * range - 1;
    
    let randomValue;
    do {
      if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
        const array = new Uint32Array(1);
        crypto.getRandomValues(array);
        randomValue = array[0];
      } else {
        // Fallback for Node.js
        const nodeCrypto = require('crypto');
        randomValue = nodeCrypto.randomBytes(4).readUInt32BE(0);
      }
    } while (randomValue > maxValidValue);
    
    return min + (randomValue % range);
  }

  /**
   * Generate a cryptographically secure random string
   */
  generateSecureString(length: number): string {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    return this.generateChars(length, charset);
  }

  /**
   * Generate a memorable password with mixed case, numbers, and symbols
   */
  generateMemorablePassword(length: number): string {
    const parts = [];
    const remainingLength = length;
    
    // Add at least one of each type
    parts.push(this.generateChars(1, 'A-Z')); // Uppercase
    parts.push(this.generateChars(1, 'a-z')); // Lowercase
    parts.push(this.generateChars(1, '0-9')); // Number
    parts.push(this.generateChars(1, '!@#$%^&*')); // Symbol
    
    // Fill the rest with mixed characters
    const remaining = remainingLength - parts.length;
    if (remaining > 0) {
      parts.push(this.generateChars(remaining, 'A-Za-z0-9!@#$%^&*'));
    }
    
    // Shuffle the parts
    const combined = parts.join('');
    const shuffled = combined.split('').sort(() => this.getSecureRandomInt(0, 1) - 0.5).join('');
    
    return shuffled.slice(0, length);
  }
} 