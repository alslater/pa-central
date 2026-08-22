import '@testing-library/jest-dom/vitest'

// jsdom doesn't implement requestAnimationFrame; run callbacks synchronously
window.requestAnimationFrame = (cb: FrameRequestCallback) => { cb(0); return 0 }

// jsdom doesn't implement matchMedia; provide a minimal stub
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  }),
})

// jsdom doesn't implement ResizeObserver; recharts' ResponsiveContainer
// requires it to observe its wrapper element's size.
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
window.ResizeObserver = ResizeObserverStub as unknown as typeof ResizeObserver
