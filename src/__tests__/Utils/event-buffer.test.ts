import { jest } from '@jest/globals'
import { makeEventBuffer } from '../../Utils/event-buffer'
import type { ILogger } from '../../Utils/logger'

const makeLogger = (): ILogger => ({
	level: 'silent',
	child: () => makeLogger(),
	trace: jest.fn(),
	debug: jest.fn(),
	info: jest.fn(),
	warn: jest.fn(),
	error: jest.fn()
})

describe('event-buffer — connection stability cleanup', () => {
	beforeEach(() => {
		jest.useFakeTimers()
	})

	afterEach(() => {
		jest.useRealTimers()
	})

	describe('removeAllListeners() cleanup', () => {
		it('clears pending bufferTimeout on disconnect so it cannot fire after teardown', () => {
			const ev = makeEventBuffer(makeLogger())

			// Start buffering — this schedules the internal 30s safety timeout
			ev.buffer()
			expect(ev.isBuffering()).toBe(true)

			// Remove all listeners (simulates socket teardown)
			ev.removeAllListeners()

			// Advance time past the buffer-safety timeout — nothing should throw
			expect(() => jest.advanceTimersByTime(40000)).not.toThrow()

			// Buffering state should have been reset
			expect(ev.isBuffering()).toBe(false)
		})

		it('cancels tracked buffered-function timeouts so they do not fire after disconnect', async () => {
			const logger = makeLogger()
			const ev = makeEventBuffer(logger)

			const work = jest.fn<() => Promise<void>>().mockResolvedValue(undefined)
			const buffered = ev.createBufferedFunction(work)

			// Run the buffered function — schedules a 100ms flush timeout inside
			await buffered()

			// Tear down before the 100ms fires
			ev.removeAllListeners()

			// Should not throw or call the logger with unexpected errors
			expect(() => jest.advanceTimersByTime(200)).not.toThrow()
		})

		it('resets bufferCount to 0 on disconnect so a reconnected buffer starts clean', () => {
			const ev = makeEventBuffer(makeLogger())

			// Increment buffer count by starting two nested buffers
			ev.buffer()
			ev.buffer()

			ev.removeAllListeners()

			// After teardown and a fresh buffer() call the state should be clean
			ev.buffer()
			expect(ev.isBuffering()).toBe(true)
			// Flush should succeed without error
			expect(() => ev.flush()).not.toThrow()
		})

		it('clears historyCache to prevent stale deduplication across reconnections', () => {
			const ev = makeEventBuffer(makeLogger())

			// Emit a history-set event to populate the cache
			ev.emit('messaging-history.set', {
				chats: [{ id: 'chat-1@s.whatsapp.net' } as any],
				messages: [],
				contacts: [],
				isLatest: false
			})

			// Tear down
			ev.removeAllListeners()

			// After reconnect the same history event should not be silently deduplicated
			// (we verify by re-emitting and checking it reaches the listener)
			const received: string[] = []
			ev.on('messaging-history.set', (data: any) => {
				received.push(data.chats?.[0]?.id)
			})

			ev.emit('messaging-history.set', {
				chats: [{ id: 'chat-1@s.whatsapp.net' } as any],
				messages: [],
				contacts: [],
				isLatest: false
			})

			expect(received).toContain('chat-1@s.whatsapp.net')
		})
	})

	describe('createBufferedFunction timeout tracking', () => {
		it('does not schedule overlapping flush timeouts when only one buffer is active', async () => {
			const timerSpy = jest.spyOn(global, 'setTimeout')

			const ev = makeEventBuffer(makeLogger())
			const work = jest.fn<() => Promise<void>>().mockResolvedValue(undefined)
			const buffered = ev.createBufferedFunction(work)

			await buffered()

			// Only one 100ms tracking timeout should have been set for this run
			const trackingTimeouts = timerSpy.mock.calls.filter(call => call[1] === 100)
			expect(trackingTimeouts.length).toBe(1)

			timerSpy.mockRestore()
		})
	})
})
