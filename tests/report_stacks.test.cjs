"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const {
  create,
  buildChronological,
  buildFlame,
  findFocus,
  frameKey,
} = require("../fault_report/stacks.js");
const frame = (label, file = "/app/main", extra = {}) => ({
  label,
  file,
  app: true,
  ...extra,
});
const event = (id, rootFirst, time = id) => ({
  id,
  time,
  stack: rootFirst.slice().reverse(),
});

test("chronological merging keeps every fault column and only merges adjacent full prefixes", () => {
  const a = frame("root"),
    b = frame("work"),
    other = frame("other root");
  const result = buildChronological([
    event(1, [a, b]),
    event(2, [a, b]),
    event(3, [other, b]),
    event(4, [a, b]),
  ]);
  assert.equal(result.events.length, 4);
  assert.deepEqual(
    result.cells.filter((c) => c.depth === 1).map((c) => [c.start, c.end]),
    [
      [0, 2],
      [2, 3],
      [3, 4],
    ],
  );
  assert.equal(
    result.cells.filter((c) => c.depth === 1).reduce((n, c) => n + c.count, 0),
    4,
  );
});

test("binary identity and unresolved state participate in prefix identity", () => {
  const a = frame("same", "/first.so"),
    b = frame("same", "/second.so");
  const c = frame("same", "/first.so", { unresolved: true });
  assert.equal(
    buildChronological([event(1, [a]), event(2, [b]), event(3, [c])]).cells
      .length,
    3,
  );
  assert.equal(
    buildFlame([event(1, [a]), event(2, [b]), event(3, [c])]).children.length,
    3,
  );
});

test("flame aggregates counts by complete path and preserves recursion", () => {
  const r = frame("recursive"),
    leaf = frame("leaf");
  const result = buildFlame([
    event(1, [r, r, leaf]),
    event(2, [r, r, leaf]),
    event(3, [r, leaf]),
  ]);
  assert.equal(result.count, 3);
  const rootFrame = result.children[0];
  assert.equal(rootFrame.count, 3);
  assert.equal(rootFrame.children[0].count, 2);
  assert.equal(rootFrame.children[0].frame.label, "recursive");
  assert.equal(rootFrame.children[0].children[0].frame.label, "leaf");
  assert.equal(rootFrame.children[1].count, 1);
  const focused = findFocus(result, [frameKey(r), frameKey(r)]);
  assert.equal(focused.count, 2);
  assert.equal(findFocus(result, [frameKey(frame("absent"))]), null);
});

test("missing stacks are explicit and remain in the flame denominator", () => {
  const data = [event(1, []), event(2, [frame("main")]), event(3, [])];
  const result = buildFlame(data);
  assert.equal(result.count, 3);
  const missing = result.children.find((child) => child.frame.missing);
  assert.equal(missing.count, 2);
  assert.equal(missing.frame.label, "No captured stack");
  assert.equal(
    result.children.reduce((n, child) => n + child.count, 0),
    3,
  );
  assert.equal(
    buildChronological(data).cells.filter((cell) => cell.frame.missing).length,
    2,
  );
});

test("first touch is earliest time, not input order or an inferred duration", () => {
  const r = frame("root");
  const result = buildFlame([
    event(1, [r], 9),
    event(2, [r], 2),
    event(3, [r], 5),
  ]);
  assert.equal(result.children[0].firstTouch, 2);
  assert.equal(result.children[0].representative.id, 2);
  assert.equal(result.children[0].count, 3);
  assert.equal(result.children[0].duration, undefined);
});

test("chronological windows use filtered offsets and limit zero means all", () => {
  const events = Array.from({ length: 6 }, (_, i) => event(i, [frame("root")]));
  assert.deepEqual(
    buildChronological(events, { start: 2, limit: 2 }).events.map((e) => e.id),
    [2, 3],
  );
  assert.equal(
    buildChronological(events, { start: 2, limit: 0 }).events.length,
    4,
  );
  assert.equal(buildChronological(events, { start: 999, limit: 10 }).start, 5);
  assert.equal(buildChronological(events, { start: -2, limit: 1 }).start, 0);
});

test("empty selections and stacks named like missing placeholders remain distinct", () => {
  assert.equal(buildChronological([]).cells.length, 0);
  assert.equal(buildFlame([]).count, 0);
  assert.equal(buildFlame([]).children.length, 0);
  assert.equal(
    buildFlame([event(1, []), event(2, [frame("No captured stack", "")])])
      .children.length,
    2,
  );
});

test("ending at a caller does not inflate the deeper frame's fault count", () => {
  const r = frame("root"),
    leaf = frame("leaf");
  const result = buildFlame([event(1, [r]), event(2, [r, leaf])]);
  assert.equal(result.children[0].count, 2);
  assert.equal(result.children[0].children[0].count, 1);
});

test("large captures avoid spread-argument limits and retain the exact denominator", () => {
  const shared = frame("root");
  const events = Array.from({ length: 150000 }, (_, i) => event(i, [shared]));
  const result = buildChronological(events);
  assert.equal(result.events.length, 150000);
  assert.equal(result.cells.length, 1);
  assert.equal(result.cells[0].count, 150000);
  assert.equal(result.cells[0].firstTouch, 0);
  assert.equal(result.cells[0].lastTouch, 149999);
  assert.equal(buildFlame(events).children[0].count, 150000);
});

function fakeSurface() {
  const handlers = new Map(),
    attributes = new Map();
  const ctx = new Proxy(
    { measureText: (text) => ({ width: text.length * 6 }) },
    {
      get(target, property) {
        return target[property] || (() => {});
      },
    },
  );
  const canvas = {
    style: {},
    getContext: () => ctx,
    addEventListener: (type, handler) => handlers.set(type, handler),
    removeEventListener: (type) => handlers.delete(type),
    setAttribute: (name, value) => attributes.set(name, value),
    getBoundingClientRect: () => ({
      left: 100,
      top: 200,
      width: 600,
      height: Number.parseFloat(canvas.style.height),
    }),
  };
  const tooltip = {
    style: {},
    offsetWidth: 200,
    offsetHeight: 100,
    textContent: "",
  };
  return {
    canvas,
    scroll: { clientWidth: 600 },
    tooltip,
    handlers,
    attributes,
  };
}

test("canvas selection and range zoom hit the exact column, including merged frames", () => {
  const surface = fakeSurface(),
    selections = [],
    ranges = [];
  const renderer = create({
    ...surface,
    onSelect: (e) => selections.push(e.id),
    onRange: (start, limit) => ranges.push([start, limit]),
  });
  const root = frame("root");
  const events = Array.from({ length: 6 }, (_, i) => ({
    ...event(10 + i, [root, frame(i < 4 ? "early" : "late")]),
    source: "app",
    major: true,
  }));
  renderer.render({
    events,
    start: 2,
    limit: 4,
    mode: "chronological",
    sources: { app: { path: "/app/main" } },
  });
  surface.handlers.get("click")({ clientX: 100 + 375, clientY: 200 + 25 });
  assert.deepEqual(selections, [14]);
  surface.handlers.get("dblclick")({ clientX: 100 + 75, clientY: 200 + 25 });
  assert.deepEqual(ranges[0], [2, 2]);
  let prevented = false;
  surface.handlers.get("wheel")({
    clientX: 100 + 450,
    clientY: 200 + 25,
    ctrlKey: true,
    deltaY: -1,
    preventDefault() {
      prevented = true;
    },
  });
  assert.equal(prevented, true);
  assert.deepEqual(ranges[1], [3, 3]);
  surface.handlers.get("mousemove")({ clientX: 100 + 375, clientY: 200 + 25 });
  assert.match(surface.tooltip.textContent, /late\n\/app\/main\n/);
  assert.match(
    surface.tooltip.textContent,
    /Selected column: #5 · captured #14/,
  );
  renderer.destroy();
  assert.equal(surface.handlers.size, 0);
});

test("flame focus labels are refreshed on render, not inferred representative selections", () => {
  const surface = fakeSurface(),
    focuses = [],
    selected = [];
  const renderer = create({
    ...surface,
    onFocus: (label, count) => focuses.push([label, count]),
    onSelect: (sample) => selected.push(sample.id),
  });
  const state = {
    events: [
      event(1, [frame("root"), frame("leaf")]),
      event(2, [frame("root")]),
    ],
    sources: {},
    mode: "flame",
  };
  renderer.render(state);
  surface.handlers.get("click")({ clientX: 101, clientY: 225 });
  assert.deepEqual(focuses.at(-1), ["leaf", 1]);
  renderer.render(state);
  assert.deepEqual(focuses.at(-1), ["leaf", 1]);
  surface.handlers.get("dblclick")({ clientX: 101, clientY: 201 });
  assert.deepEqual(selected, []);
  renderer.resetFocus();
  renderer.render(state);
  assert.deepEqual(focuses.at(-1), ["", 2]);
});
