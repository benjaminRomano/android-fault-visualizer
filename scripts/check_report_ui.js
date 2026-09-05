// Pass this function to playwright-cli run-code with a generated report open.
async (page) => {
  const require = (value, message) => {
    if (!value) throw Error(message);
  };
  await page.locator("#run").selectOption("0");
  await page.locator("#reset").click();
  await page.locator("#tab-pages").click();
  await page.locator("#view").selectOption("address");
  await page.locator("#axis").selectOption("order");
  const capture = await page.evaluate(() => ({
    total: REPORT.runs[0].events.length,
    plotted: REPORT.runs[0].events.filter((e) => e.addressPlot !== false)
      .length,
    plottedMajors: REPORT.runs[0].events.filter(
      (e) => e.major && e.addressPlot !== false,
    ).length,
    addressDeltas: REPORT.runs[0].events.filter(
      (e, i, all) =>
        i > 0 && e.addressPlot !== false && all[i - 1].addressPlot !== false,
    ).length,
    majors: REPORT.runs[0].events.filter((e) => e.major).length,
    firstMajor: REPORT.runs[0].events.find((e) => e.major)?.id,
  }));
  const majorIndices = await page
    .locator("#access")
    .evaluate((el) => el.data.find((t) => t.name === "Major").x);
  require(majorIndices.length ===
    capture.plottedMajors, "Major plot count differs from capture");
  await page.locator("#kind").selectOption("all");
  const all = await page.locator("#access").evaluate((el) => ({
    n: el.data.reduce((n, t) => n + t.x.length, 0),
    major: el.data.find((t) => t.name === "Major").x,
  }));
  require(all.n === capture.plotted, "Overview omitted plottable events");
  require(JSON.stringify(all.major) ===
    JSON.stringify(majorIndices), "Minor toggle renumbered major faults");
  if (capture.total > 1) {
    const end = Math.floor(capture.total / 2);
    await page
      .locator("#access")
      .evaluate(
        (el, end) => Plotly.relayout(el, { "xaxis.range": [1, end] }),
        end,
      );
    await page.locator("#useRange").click();
    require((await page.locator("#selectionCount").textContent()).startsWith(
      end.toLocaleString() + " matching faults",
    ), "Plot zoom range did not filter original event indices");
    await page.locator("#clearRange").click();
  }
  await page.locator("#view").selectOption("delta-address");
  const deltas = await page
    .locator("#access")
    .evaluate((el) => el.data.reduce((n, t) => n + t.x.length, 0));
  require(deltas ===
    capture.addressDeltas, "Address deltas must not bridge unplottable events");
  await page.locator("#kind").selectOption("major");
  await page.locator("#tab-stacks").click();
  await page.locator("#stackLimit").selectOption("50");
  if (capture.majors) {
    await page.locator("#stackScroll").scrollIntoViewIfNeeded();
    await page.locator("#stackScroll").evaluate((el) => {
      el.scrollTop = 0;
    });
    const box = await page.locator("#stacks").boundingBox();
    await page.mouse.click(box.x + 1, box.y + 5);
    require((await page.locator("#detail").textContent()).includes(
      "#" + capture.firstMajor + " ·",
    ), "Stack click selected wrong event");
  }
  await page.locator("#tab-flame").click();
  require((await page.locator("#stacks").getAttribute("aria-label")).includes(
    capture.majors + " matching faults",
  ), "Flame denominator differs from filter");
  await page.locator("#search").fill("__no_such_fault_for_ui_qa__");
  require((await page.locator("#selectionCount").textContent()).startsWith(
    "0 matching faults",
  ), "Empty search retained events");
  require((await page.locator("#stacks").getAttribute("aria-label")).includes(
    "0 matching faults",
  ), "Empty search retained stacks");
  await page.locator("#reset").click();
  await page.locator("#tab-pages").click();
  await page.locator("#view").selectOption("address");
  await page.locator("#axis").selectOption("time");
  const viewport = page.viewportSize();
  await page.setViewportSize({ width: 390, height: 844 });
  const mobile = await page.evaluate(() => ({
    width: innerWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }));
  require(mobile.scrollWidth <=
    mobile.width, "Narrow-screen horizontal overflow");
  if (viewport) await page.setViewportSize(viewport);
  return {
    capture,
    deltaPoints: deltas,
    mobile,
    checks:
      "counts, stable indices, shared range, deltas, exact selection, flame weights, empty filters, narrow layout",
  };
};
