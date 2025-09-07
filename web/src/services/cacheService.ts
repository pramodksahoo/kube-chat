/**
 * Cache Service - Intelligent caching for API responses
 * Provides HTTP cache, memory cache, and cache invalidation strategies
 */


export interface CacheEntry<T = any> {
  data: T;
  timestamp: Date;
  etag?: string;
  maxAge: number;
  lastAccessed: Date;
  accessCount: number;
}

export interface CacheConfig {
  maxMemoryEntries: number;
  defaultTTL: number;
  gcInterval: number;
  enableCompression: boolean;
}

export interface CacheStats {
  totalEntries: number;
  memoryUsage: number;
  hitRate: number;
  missRate: number;
  totalRequests: number;
  totalHits: number;
  totalMisses: number;
}

// Cache key generation
export class CacheKeyBuilder {
  static forResourceList(params?: {
    namespace?: string;
    kind?: string;
    labelSelector?: string;
  }): string {
    const parts = ['resources'];
    
    if (params?.namespace) parts.push(`ns:${params.namespace}`);
    if (params?.kind) parts.push(`kind:${params.kind}`);
    if (params?.labelSelector) parts.push(`labels:${params.labelSelector}`);
    
    return parts.join('|');
  }

  static forResource(kind: string, name: string, namespace?: string): string {
    return namespace 
      ? `resource|${kind}|${name}|${namespace}`
      : `resource|${kind}|${name}|cluster`;
  }

  static forResourceLogs(kind: string, name: string, namespace?: string, options?: {
    container?: string;
    tailLines?: number;
  }): string {
    const base = CacheKeyBuilder.forResource(kind, name, namespace);
    const parts = [base, 'logs'];
    
    if (options?.container) parts.push(`container:${options.container}`);
    if (options?.tailLines) parts.push(`tail:${options.tailLines}`);
    
    return parts.join('|');
  }

  static forResourceEvents(kind: string, name: string, namespace?: string): string {
    return `${CacheKeyBuilder.forResource(kind, name, namespace)}|events`;
  }

  static forResourceDescribe(kind: string, name: string, namespace?: string): string {
    return `${CacheKeyBuilder.forResource(kind, name, namespace)}|describe`;
  }
}

// LRU Cache implementation
class LRUCache<T> {
  private cache = new Map<string, CacheEntry<T>>();
  private accessOrder = new Map<string, number>();
  private accessCounter = 0;

  private maxSize: number;
  
  constructor(maxSize: number) {
    this.maxSize = maxSize;
  }

  set(key: string, entry: CacheEntry<T>): void {
    // Remove oldest entry if at capacity
    if (this.cache.size >= this.maxSize && !this.cache.has(key)) {
      this.evictLRU();
    }

    this.cache.set(key, entry);
    this.accessOrder.set(key, ++this.accessCounter);
  }

  get(key: string): CacheEntry<T> | undefined {
    const entry = this.cache.get(key);
    if (entry) {
      // Update access tracking
      entry.lastAccessed = new Date();
      entry.accessCount++;
      this.accessOrder.set(key, ++this.accessCounter);
    }
    return entry;
  }

  delete(key: string): boolean {
    this.accessOrder.delete(key);
    return this.cache.delete(key);
  }

  clear(): void {
    this.cache.clear();
    this.accessOrder.clear();
    this.accessCounter = 0;
  }

  size(): number {
    return this.cache.size;
  }

  keys(): string[] {
    return Array.from(this.cache.keys());
  }

  private evictLRU(): void {
    let oldestKey = '';
    let oldestAccess = Infinity;

    for (const [key, access] of this.accessOrder) {
      if (access < oldestAccess) {
        oldestAccess = access;
        oldestKey = key;
      }
    }

    if (oldestKey) {
      this.delete(oldestKey);
    }
  }
}

// Main cache service
export class CacheService {
  private config: CacheConfig;
  private memoryCache: LRUCache<any>;
  private stats: CacheStats;
  private gcInterval: NodeJS.Timeout | null = null;
  
  constructor(config: CacheConfig) {
    this.config = config;
    this.memoryCache = new LRUCache(config.maxMemoryEntries);
    this.stats = {
      totalEntries: 0,
      memoryUsage: 0,
      hitRate: 0,
      missRate: 0,
      totalRequests: 0,
      totalHits: 0,
      totalMisses: 0,
    };

    this.startGarbageCollection();
  }

  // Cache operations
  async get<T>(key: string): Promise<T | null> {
    this.stats.totalRequests++;

    // Check memory cache first
    const memoryEntry = this.memoryCache.get(key);
    if (memoryEntry && !this.isExpired(memoryEntry)) {
      this.stats.totalHits++;
      this.updateHitRate();
      return memoryEntry.data;
    }

    // Check browser cache storage
    try {
      const browserEntry = await this.getBrowserCache<T>(key);
      if (browserEntry && !this.isExpired(browserEntry)) {
        // Promote to memory cache
        this.memoryCache.set(key, browserEntry);
        this.stats.totalHits++;
        this.updateHitRate();
        return browserEntry.data;
      }
    } catch (error) {
      console.warn('Browser cache read failed:', error);
    }

    this.stats.totalMisses++;
    this.updateHitRate();
    return null;
  }

  async set<T>(
    key: string, 
    data: T, 
    options: {
      maxAge?: number;
      etag?: string;
      priority?: 'high' | 'medium' | 'low';
    } = {}
  ): Promise<void> {
    const maxAge = options.maxAge ?? this.config.defaultTTL;
    const entry: CacheEntry<T> = {
      data,
      timestamp: new Date(),
      etag: options.etag,
      maxAge,
      lastAccessed: new Date(),
      accessCount: 1,
    };

    // Always store in memory cache
    this.memoryCache.set(key, entry);

    // Store in browser cache based on priority
    if (options.priority !== 'low') {
      try {
        await this.setBrowserCache(key, entry);
      } catch (error) {
        console.warn('Browser cache write failed:', error);
      }
    }

    this.updateStats();
  }

  async delete(key: string): Promise<void> {
    this.memoryCache.delete(key);
    
    try {
      await this.deleteBrowserCache(key);
    } catch (error) {
      console.warn('Browser cache delete failed:', error);
    }
    
    this.updateStats();
  }

  async clear(): Promise<void> {
    this.memoryCache.clear();
    
    try {
      await this.clearBrowserCache();
    } catch (error) {
      console.warn('Browser cache clear failed:', error);
    }
    
    this.updateStats();
  }

  // Cache invalidation strategies
  async invalidatePattern(pattern: RegExp): Promise<void> {
    const keys = this.memoryCache.keys();
    const toDelete = keys.filter(key => pattern.test(key));
    
    for (const key of toDelete) {
      await this.delete(key);
    }
  }

  async invalidateNamespace(namespace: string): Promise<void> {
    const pattern = new RegExp(`ns:${namespace}|\\|${namespace}\\|`);
    await this.invalidatePattern(pattern);
  }

  async invalidateResource(kind: string, name: string, namespace?: string): Promise<void> {
    const resourceKey = CacheKeyBuilder.forResource(kind, name, namespace);
    const pattern = new RegExp(`^${resourceKey.replace('|', '\\|')}(\\||$)`);
    await this.invalidatePattern(pattern);
  }

  async invalidateResourceList(): Promise<void> {
    const pattern = /^resources/;
    await this.invalidatePattern(pattern);
  }

  // Cache warming
  async warmCache(keys: string[]): Promise<void> {
    // This would be implemented by the API client to pre-fetch data
    console.log(`Warming cache for ${keys.length} keys`);
  }

  // Statistics and monitoring
  getStats(): CacheStats {
    return { ...this.stats };
  }

  // Conditional requests support
  async getWithETag<T>(key: string): Promise<{ data: T; etag?: string } | null> {
    const cached = await this.get<T>(key);
    if (!cached) return null;

    const entry = this.memoryCache.get(key) || await this.getBrowserCache<T>(key);
    return {
      data: cached,
      etag: entry?.etag,
    };
  }

  // Batch operations
  async getBatch<T>(keys: string[]): Promise<Map<string, T | null>> {
    const results = new Map<string, T | null>();
    
    await Promise.all(
      keys.map(async (key) => {
        const value = await this.get<T>(key);
        results.set(key, value);
      })
    );

    return results;
  }

  async setBatch<T>(entries: Array<{ key: string; data: T; options?: any }>): Promise<void> {
    await Promise.all(
      entries.map(({ key, data, options }) => 
        this.set(key, data, options)
      )
    );
  }

  // Private methods
  private isExpired(entry: CacheEntry): boolean {
    const age = Date.now() - entry.timestamp.getTime();
    return age > entry.maxAge;
  }

  private updateHitRate(): void {
    if (this.stats.totalRequests > 0) {
      this.stats.hitRate = this.stats.totalHits / this.stats.totalRequests;
      this.stats.missRate = this.stats.totalMisses / this.stats.totalRequests;
    }
  }

  private updateStats(): void {
    this.stats.totalEntries = this.memoryCache.size();
    this.stats.memoryUsage = this.estimateMemoryUsage();
    this.updateHitRate();
  }

  private estimateMemoryUsage(): number {
    // Rough estimation of memory usage
    return this.memoryCache.size() * 1024; // 1KB per entry estimate
  }

  private startGarbageCollection(): void {
    if (this.gcInterval) return;

    this.gcInterval = setInterval(() => {
      this.runGarbageCollection();
    }, this.config.gcInterval);
  }

  private runGarbageCollection(): void {
    const keys = this.memoryCache.keys();
    let cleaned = 0;

    for (const key of keys) {
      const entry = this.memoryCache.get(key);
      if (entry && this.isExpired(entry)) {
        this.memoryCache.delete(key);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      console.debug(`Cache GC: cleaned ${cleaned} expired entries`);
      this.updateStats();
    }
  }

  // Browser cache operations (using IndexedDB or Cache API)
  private async getBrowserCache<T>(key: string): Promise<CacheEntry<T> | null> {
    try {
      const stored = localStorage.getItem(`cache_${key}`);
      if (!stored) return null;

      const entry = JSON.parse(stored) as CacheEntry<T>;
      entry.timestamp = new Date(entry.timestamp);
      entry.lastAccessed = new Date(entry.lastAccessed);

      return entry;
    } catch {
      return null;
    }
  }

  private async setBrowserCache<T>(key: string, entry: CacheEntry<T>): Promise<void> {
    try {
      localStorage.setItem(`cache_${key}`, JSON.stringify(entry));
    } catch (error) {
      // Handle quota exceeded
      if (error instanceof DOMException && error.code === 22) {
        await this.clearOldestBrowserCache();
        localStorage.setItem(`cache_${key}`, JSON.stringify(entry));
      }
    }
  }

  private async deleteBrowserCache(key: string): Promise<void> {
    localStorage.removeItem(`cache_${key}`);
  }

  private async clearBrowserCache(): Promise<void> {
    const keys = Object.keys(localStorage);
    const cacheKeys = keys.filter(key => key.startsWith('cache_'));
    
    for (const key of cacheKeys) {
      localStorage.removeItem(key);
    }
  }

  private async clearOldestBrowserCache(): Promise<void> {
    const keys = Object.keys(localStorage);
    const cacheKeys = keys.filter(key => key.startsWith('cache_'));
    
    if (cacheKeys.length === 0) return;

    // Remove oldest entries (simplified - would use actual timestamps in production)
    const toRemove = cacheKeys.slice(0, Math.ceil(cacheKeys.length * 0.1));
    for (const key of toRemove) {
      localStorage.removeItem(key);
    }
  }

  // Cleanup
  destroy(): void {
    if (this.gcInterval) {
      clearInterval(this.gcInterval);
      this.gcInterval = null;
    }
    this.memoryCache.clear();
  }
}

// Default cache instance
const defaultConfig: CacheConfig = {
  maxMemoryEntries: 1000,
  defaultTTL: 5 * 60 * 1000, // 5 minutes
  gcInterval: 60 * 1000, // 1 minute
  enableCompression: false,
};

export const cacheService = new CacheService(defaultConfig);

// Cache decorators
export function cached(ttl: number = defaultConfig.defaultTTL) {
  return function (target: any, propertyName: string, descriptor: PropertyDescriptor) {
    const method = descriptor.value;

    descriptor.value = async function (...args: any[]) {
      const key = `${target.constructor.name}.${propertyName}(${JSON.stringify(args)})`;
      
      // Try cache first
      const cached = await cacheService.get(key);
      if (cached !== null) {
        return cached;
      }

      // Execute method and cache result
      const result = await method.apply(this, args);
      await cacheService.set(key, result, { maxAge: ttl });
      
      return result;
    };

    return descriptor;
  };
}