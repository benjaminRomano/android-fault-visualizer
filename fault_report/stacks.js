/* Original, dependency-free fault stack renderer. Stacks arrive leaf first.
 * Width is fault count in both modes, never elapsed time or sampled duration.
 */
(function (global) {
  "use strict";
  const ROW = 20,
    AXIS = 44;
  const missing = { label: "No captured stack", file: "", missing: true };
  const frameKey = (frame) =>
    JSON.stringify([
      frame.label || "",
      frame.file || "",
      !!frame.app,
      !!frame.unresolved,
      !!frame.missing,
    ]);
  const stackOf = (event) =>
    event.stack?.length ? event.stack.slice().reverse() : [missing];
  const timeOf = (event) => (Number.isFinite(event.time) ? event.time : null);

  function buildChronological(events, { start = 0, limit = 0 } = {}) {
    start = Math.max(
      0,
      Math.min(Math.max(0, events.length - 1), Math.floor(start) || 0),
    );
    limit = Math.max(0, Math.floor(limit) || 0);
    const shown = events.slice(start, limit ? start + limit : undefined);
    const stacks = shown.map(stackOf),
      interned = new Map();
    const prefixes = stacks.map((stack) => {
      let parent = 0;
      return stack.map((frame) => {
        const key = JSON.stringify([parent, frameKey(frame)]);
        if (!interned.has(key)) interned.set(key, interned.size + 1);
        parent = interned.get(key);
        return parent;
      });
    });
    const depth = stacks.reduce(
        (maximum, stack) => Math.max(maximum, stack.length),
        1,
      ),
      cells = [];
    for (let row = 0; row < depth; row++) {
      for (let i = 0; i < shown.length; ) {
        if (!stacks[i][row]) {
          i++;
          continue;
        }
        let end = i + 1;
        while (end < shown.length && prefixes[end][row] === prefixes[i][row])
          end++;
        let firstTouch = null,
          lastTouch = null;
        for (let index = i; index < end; index++) {
          const time = timeOf(shown[index]);
          if (time !== null) {
            firstTouch =
              firstTouch === null ? time : Math.min(firstTouch, time);
            lastTouch = lastTouch === null ? time : Math.max(lastTouch, time);
          }
        }
        cells.push({
          frame: stacks[i][row],
          depth: row,
          start: i,
          end,
          count: end - i,
          firstTouch,
          lastTouch,
        });
        i = end;
      }
    }
    return { events: shown, total: events.length, start, depth, cells };
  }

  function buildFlame(events) {
    const node = (frame, path) => ({
      frame,
      path,
      count: 0,
      firstTouch: null,
      lastTouch: null,
      representative: null,
      children: [],
      byKey: new Map(),
    });
    const root = node(null, []);
    function visit(current, event) {
      current.count++;
      const time = timeOf(event);
      if (
        current.representative === null ||
        (time !== null &&
          (current.firstTouch === null || time < current.firstTouch))
      ) {
        current.representative = event;
      }
      if (time !== null) {
        current.firstTouch =
          current.firstTouch === null
            ? time
            : Math.min(current.firstTouch, time);
        current.lastTouch =
          current.lastTouch === null ? time : Math.max(current.lastTouch, time);
      }
    }
    for (const event of events) {
      let current = root;
      visit(current, event);
      for (const frame of stackOf(event)) {
        const key = frameKey(frame);
        if (!current.byKey.has(key))
          current.byKey.set(key, node(frame, [...current.path, key]));
        current = current.byKey.get(key);
        visit(current, event);
      }
    }
    function finish(current) {
      current.children = [...current.byKey.values()].sort(
        (a, b) =>
          b.count - a.count ||
          (a.firstTouch ?? Infinity) - (b.firstTouch ?? Infinity) ||
          frameKey(a.frame).localeCompare(frameKey(b.frame)),
      );
      delete current.byKey;
      current.children.forEach(finish);
    }
    finish(root);
    return root;
  }

  function findFocus(root, path) {
    let current = root;
    for (const key of path) {
      current = current.children.find((child) => frameKey(child.frame) === key);
      if (!current) return null;
    }
    return current;
  }

  function create({ canvas, scroll, tooltip, onSelect, onRange, onFocus }) {
    const ctx = canvas.getContext("2d");
    let state,
      model,
      hits = [],
      focusPath = [],
      width = 1,
      height = 1;
    const listeners = [];
    function listen(type, callback, options) {
      canvas.addEventListener(type, callback, options);
      listeners.push([type, callback, options]);
    }
    function callback(name, ...args) {
      const handler = state?.[name] || { onRange, onFocus, onSelect }[name];
      if (handler) handler(...args);
    }
    function fit(text, available) {
      if (available < 10) return "";
      if (ctx.measureText(text).width <= available) return text;
      let lo = 0,
        hi = text.length;
      while (lo < hi) {
        const mid = Math.ceil((lo + hi) / 2);
        if (ctx.measureText(text.slice(0, mid) + "…").width <= available)
          lo = mid;
        else hi = mid - 1;
      }
      return text.slice(0, lo) + "…";
    }
    function paint(hit) {
      const { x, y, w, frame } = hit;
      ctx.save();
      ctx.beginPath();
      ctx.rect(x, y, w, ROW - 1);
      ctx.clip();
      ctx.fillStyle = frame.missing
        ? "#f2f2f2"
        : frame.app
          ? "#b6d6f1"
          : "#e0e3e6";
      ctx.fillRect(x, y, Math.max(0, w - 1), ROW - 1);
      if (frame.unresolved) {
        ctx.strokeStyle = "#b7c0c9";
        ctx.beginPath();
        for (let dx = -ROW; dx < w; dx += 8) {
          ctx.moveTo(x + dx, y + ROW);
          ctx.lineTo(x + dx + ROW, y);
        }
        ctx.stroke();
      }
      ctx.fillStyle = frame.missing ? "#666" : "#18232c";
      ctx.fillText(
        fit(frame.label || "Unresolved frame", w - 10),
        x + 5,
        y + 14,
      );
      ctx.restore();
      if (hit.selected) {
        ctx.strokeStyle = "#123e69";
        ctx.lineWidth = 1.5;
        ctx.strokeRect(x + 0.75, y + 0.75, Math.max(0, w - 1.5), ROW - 2.5);
      }
      hits.push(hit);
    }
    function size(depth) {
      width = Math.max(240, scroll.clientWidth || canvas.clientWidth || 800);
      height = Math.max(104, depth * ROW + AXIS);
      const dpr = Math.min(global.devicePixelRatio || 1, 2);
      canvas.style.width = width + "px";
      canvas.style.height = height + "px";
      canvas.width = Math.round(width * dpr);
      canvas.height = Math.round(height * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, width, height);
      ctx.font = "11px -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif";
      ctx.textBaseline = "alphabetic";
    }
    function render(next) {
      state = next;
      hits = [];
      if (tooltip) tooltip.style.display = "none";
      if (state.mode === "flame") {
        model = buildFlame(state.events);
        let focus = findFocus(model, focusPath);
        if (!focus) {
          focusPath = [];
          focus = model;
        }
        callback("onFocus", focus.frame?.label || "", focus.count);
        const depthOf = (node) =>
          (node.frame ? 1 : 0) +
          node.children.reduce(
            (depth, child) => Math.max(depth, depthOf(child)),
            0,
          );
        size(depthOf(focus));
        const selected = state.events.find(
          (event) => event.id === state.selectedId,
        );
        const selectedPath = selected ? stackOf(selected).map(frameKey) : [];
        function drawNode(node, x, row) {
          const w = (node.count / (focus.count || 1)) * width;
          if (node.frame)
            paint({
              x,
              y: row * ROW,
              w,
              frame: node.frame,
              node,
              selected: node.path.every(
                (key, index) => selectedPath[index] === key,
              ),
            });
          let childX = x;
          for (const child of node.children) {
            drawNode(child, childX, row + (node.frame ? 1 : 0));
            childX += (child.count / (focus.count || 1)) * width;
          }
        }
        drawNode(focus, 0, 0);
        ctx.fillStyle = "#52616b";
        ctx.fillText(
          `${focus.count.toLocaleString()} faults · width = fault count · root at top`,
          5,
          height - 12,
        );
      } else {
        model = buildChronological(state.events, state);
        size(model.depth);
        const column = width / Math.max(1, model.events.length);
        for (const cell of model.cells)
          paint({
            x: cell.start * column,
            y: cell.depth * ROW,
            w: cell.count * column,
            frame: cell.frame,
            cell,
          });
        const y = height - AXIS;
        model.events.forEach((event, i) => {
          ctx.fillStyle = event.major ? "#b86b12" : "#3973b9";
          ctx.fillRect(i * column, y + 1, Math.max(0.5, column), 3);
          if (state.selectedId === event.id) {
            ctx.strokeStyle = "#123e69";
            ctx.lineWidth = 2;
            ctx.strokeRect(i * column + 1, 1, Math.max(1, column - 2), y + 3);
          }
        });
        const count = model.events.length;
        const ticks = Math.min(count, Math.max(2, Math.floor(width / 140)));
        for (let tick = 0; tick < ticks; tick++) {
          const i = Math.round((tick / Math.max(1, ticks - 1)) * (count - 1));
          const event = model.events[i],
            x = i * column;
          ctx.fillStyle = "#52616b";
          ctx.textAlign = tick === ticks - 1 ? "right" : "left";
          const tx = tick === ticks - 1 ? width - 4 : x + 4;
          ctx.fillText(`#${model.start + i + 1}`, tx, y + 19);
          ctx.fillText(
            timeOf(event) === null
              ? "time unavailable"
              : `${event.time.toFixed(3)} ms`,
            tx,
            y + 34,
          );
        }
        ctx.textAlign = "left";
      }
      if (!state.events.length) {
        ctx.fillStyle = "#52616b";
        ctx.fillText("No faults match these filters", 12, 28);
      }
      canvas.setAttribute(
        "aria-label",
        `${state.mode === "flame" ? "Aggregated" : "Chronological"} fault stacks, root at top. Width is fault count, not time. ${state.events.length} matching faults.`,
      );
    }
    function locate(event) {
      const rect = canvas.getBoundingClientRect();
      const x = ((event.clientX - rect.left) * width) / rect.width;
      const y = ((event.clientY - rect.top) * height) / rect.height;
      const hit = hits.find(
        (cell) =>
          x >= cell.x && x < cell.x + cell.w && y >= cell.y && y < cell.y + ROW,
      );
      const index = Math.min(
        (model?.events?.length || 1) - 1,
        Math.max(0, Math.floor((x / width) * (model?.events?.length || 0))),
      );
      return { hit, index };
    }
    listen("mousemove", (event) => {
      if (!state || !tooltip) return;
      const { hit, index } = locate(event);
      if (!hit) {
        tooltip.style.display = "none";
        return;
      }
      const sample =
        state.mode === "flame" ? hit.node.representative : model.events[index];
      const item = hit.node || hit.cell,
        first = item.firstTouch;
      const range = hit.cell
        ? `Filtered faults ${model.start + item.start + 1}–${model.start + item.end}`
        : "Aggregated path";
      const lines = [
        hit.frame.label,
        hit.frame.file,
        `${range} · ${item.count} fault${item.count === 1 ? "" : "s"}`,
        first === null
          ? "First touch unavailable"
          : `First touch: ${first.toFixed(3)} ms`,
      ];
      if (state.mode !== "flame")
        lines.push(
          `Selected column: #${model.start + index + 1} · captured #${sample.order ?? sample.id} · ${sample.major ? "major" : "minor"}`,
        );
      if (sample)
        lines.push(
          `${state.mode === "flame" ? "First-touch sample · " : ""}${state.stacksOnly ? "Instruction binary" : "Read source"}: ${state.sources?.[sample.source]?.path || sample.source}`,
        );
      if (state.mode === "flame" && item.count > 1)
        lines.push("Click to focus this path. Width is count, not duration.");
      tooltip.textContent = lines.filter(Boolean).join("\n");
      tooltip.style.display = "block";
      tooltip.style.left =
        Math.max(
          8,
          Math.min(
            event.clientX + 12,
            (global.innerWidth || width) - tooltip.offsetWidth - 8,
          ),
        ) + "px";
      tooltip.style.top =
        Math.max(
          8,
          Math.min(
            event.clientY + 12,
            (global.innerHeight || height) - tooltip.offsetHeight - 8,
          ),
        ) + "px";
    });
    listen("mouseleave", () => {
      if (tooltip) tooltip.style.display = "none";
    });
    listen("click", (event) => {
      if (!state) return;
      const { hit, index } = locate(event);
      if (state.mode !== "flame") {
        if (model.events[index]) callback("onSelect", model.events[index]);
      } else if (hit) {
        focusPath = hit.node.path.slice();
        callback("onFocus", hit.frame.label, hit.node.count);
        render(state);
      }
    });
    listen("dblclick", (event) => {
      if (!state || state.mode === "flame") return;
      const { hit } = locate(event);
      if (hit && hit.cell.count < model.events.length)
        callback("onRange", model.start + hit.cell.start, hit.cell.count);
    });
    listen(
      "wheel",
      (event) => {
        if (
          !state ||
          state.mode === "flame" ||
          !event.ctrlKey ||
          !model.events.length
        )
          return;
        event.preventDefault();
        const { index } = locate(event),
          old = model.events.length;
        const limit = Math.max(
          1,
          Math.min(
            model.total,
            Math.round(old * (event.deltaY > 0 ? 1.5 : 0.67)),
          ),
        );
        const start = Math.max(
          0,
          Math.min(
            model.total - limit,
            model.start + index - Math.floor((index / old) * limit),
          ),
        );
        callback("onRange", start, limit);
      },
      { passive: false },
    );
    return {
      render,
      resetFocus() {
        focusPath = [];
        callback("onFocus", "", state?.events.length || 0);
      },
      destroy() {
        listeners.forEach(([type, listener, options]) =>
          canvas.removeEventListener(type, listener, options),
        );
        if (tooltip) tooltip.style.display = "none";
      },
    };
  }
  const api = { create, buildChronological, buildFlame, findFocus, frameKey };
  global.FaultStacks = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);
