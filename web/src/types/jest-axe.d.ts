declare module 'jest-axe' {
  
  interface AxeMatchers<R = unknown> {
    toHaveNoViolations(): R;
  }
  
  export function axe(container: Element | Document, options?: unknown): Promise<unknown>;
  export function toHaveNoViolations(received: unknown): unknown;
  
  declare global {
    namespace Vi {
      // eslint-disable-next-line @typescript-eslint/no-empty-object-type
      interface Assertion<T = unknown> extends AxeMatchers<T> {}
      // eslint-disable-next-line @typescript-eslint/no-empty-object-type  
      interface AsymmetricMatchersContaining extends AxeMatchers {}
    }
  }
}