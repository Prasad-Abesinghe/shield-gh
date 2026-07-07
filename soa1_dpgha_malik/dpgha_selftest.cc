// Self-test: reproduce the paper's worked example (Table 2, §IV.B Experiment).
// 8 vehicles, single RSU. Ground truth: V3 = Smart GHA, V5 = Seq-No GHA.
// Expected from paper: β = 49.5; V3 -> SmartGHA, V5 -> SeqNoGHA, rest Normal.
#include "dpgha_detection.h"
#include <cassert>
using namespace dpgha;

int main() {
    // Build the MRT from Table 2 via a clear factory (field order explicit).
    std::vector<DpghaNodeSignals> mrt;
    auto mk = [](double dsn, uint32_t rreqR, uint32_t rrepG,
                 uint32_t dpR, uint32_t dpF, bool atk) {
        DpghaNodeSignals s; s.mean_dsn = dsn; s.rreq_received = rreqR;
        s.rrep_generated = rrepG; s.dp_received = dpR; s.dp_forwarded = dpF;
        s.is_attacker = atk; return s;
    };
    // Table 2:        DSN  RREQ_R RREP_G  DP_R   DP_F  attacker
    mrt.push_back(mk(  21,   40,    15,    550,   545, false)); // V1
    mrt.push_back(mk(  25,   60,    25,    920,   910, false)); // V2
    mrt.push_back(mk(  23,   50,    46,    850,   810, true )); // V3 Smart GHA
    mrt.push_back(mk(  18,   45,    12,    640,   630, false)); // V4
    mrt.push_back(mk( 200,   80,    75,   1400,  1370, true )); // V5 Seq-No GHA
    mrt.push_back(mk(  32,   65,    40,    960,   895, false)); // V6
    mrt.push_back(mk(  60,   41,    25,   1620,  1590, false)); // V7
    mrt.push_back(mk(  17,   39,    19,    210,   205, false)); // V8

    DpghaResult r = DetectAll(mrt);

    std::cout << "β (Eq.17) = " << r.beta << "  (paper: 49.5)\n";
    for (size_t i = 0; i < mrt.size(); i++) {
        std::cout << "  V" << (i+1)
                  << ": PLR=" << PLR(mrt[i]) << "%"
                  << " RRR=" << RRR(mrt[i]) << "%"
                  << " μ(DSN)=" << mrt[i].mean_dsn
                  << " -> " << VerdictName(r.verdicts[i]) << "\n";
    }
    std::cout << "TP=" << r.TP << " TN=" << r.TN
              << " FP=" << r.FP << " FN=" << r.FN
              << " | acc=" << r.accuracy() << "% tpr=" << r.tpr()
              << "% fpr=" << r.fpr() << "%\n";

    // Assertions matching the paper's stated outcome.
    assert(std::abs(r.beta - 49.5) < 1e-6 && "β must equal 49.5");
    assert(r.verdicts[2] == Verdict::SmartGHA && "V3 = Smart GHA");
    assert(r.verdicts[4] == Verdict::SeqNoGHA && "V5 = Seq-No GHA");
    for (size_t i = 0; i < mrt.size(); i++)
        if (i != 2 && i != 4)
            assert(r.verdicts[i] == Verdict::Normal && "others Normal");
    std::cout << "\nALL ASSERTIONS PASSED — matches paper Table 2.\n";
    return 0;
}
