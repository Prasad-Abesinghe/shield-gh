// ============================================================
//  SHIELD-GH / SDVN  —  Galle mobility + 64-RSU grid → NetAnim
//
//  Loads the SUMO-derived NS-2 mobility trace (galle_mobility.tcl) for the
//  200 vehicles, overlays a 64-RSU (8x8) grid at 250 m spacing on top of the
//  vehicular mobility trace (supervisor req. 01/07/2026), and writes a
//  NetAnim XML so a 10 s clip of the mobility + RSUs can be recorded.
//
//  Node layout:
//    nodes 0..199   : vehicles (mobility from TCL, veh{i} -> node i)
//    nodes 200..263 : 64 RSUs on a static 8x8 grid, 250 m apart
//
//  NS-3 sim starts at t=30 s of SUMO time is handled by the caller/report;
//  here we visualise the mobility. Run for --dur seconds (default 10) since
//  the supervisor only needs a 10 s NetAnim clip of the mobility trace.
//
//  Build (waf compiles all scratch/*.cc; this one has its own main):
//    ./waf build
//  Run:
//    ./build/scratch/galle_netanim --tcl=scratch/sumo/galle_scenario/galle_mobility.tcl \
//        --anim=scratch/sumo/galle_scenario/galle_netanim.xml --dur=10
// ============================================================
#include "ns3/core-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/netanim-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("GalleNetAnim");

int
main (int argc, char *argv[])
{
  uint32_t nVehicles = 200;
  uint32_t rsuRows = 8, rsuCols = 8;   // 8x8 = 64 RSUs
  double   rsuSpacing = 250.0;         // 250 m horizontally and vertically
  double   duration = 10.0;            // 10 s clip is enough for the mobility view
  // grid origin: centre the 1750x1750 m RSU grid inside the ~2.1x2.1 km net
  double   gridX0 = 173.7, gridY0 = 185.1;
  std::string tclFile = "scratch/sumo/galle_scenario/galle_mobility.tcl";
  std::string animFile = "scratch/sumo/galle_scenario/galle_netanim.xml";

  CommandLine cmd;
  cmd.AddValue ("nVehicles", "number of vehicle nodes", nVehicles);
  cmd.AddValue ("spacing", "RSU grid spacing (m)", rsuSpacing);
  cmd.AddValue ("gridX0", "RSU grid origin X (m)", gridX0);
  cmd.AddValue ("gridY0", "RSU grid origin Y (m)", gridY0);
  cmd.AddValue ("dur", "animation duration (s)", duration);
  cmd.AddValue ("tcl", "NS-2 mobility trace file", tclFile);
  cmd.AddValue ("anim", "NetAnim output XML", animFile);
  cmd.Parse (argc, argv);

  uint32_t nRsu = rsuRows * rsuCols;

  // ---- vehicle nodes (0 .. nVehicles-1) driven by the SUMO TCL trace ----
  NodeContainer vehicles;
  vehicles.Create (nVehicles);
  Ns2MobilityHelper ns2 (tclFile);
  ns2.Install (vehicles.Begin (), vehicles.End ());   // maps $node_(i) -> node i

  // ---- 64 RSU nodes on a static 8x8 grid, 250 m apart ----
  NodeContainer rsus;
  rsus.Create (nRsu);
  MobilityHelper rsuMob;
  Ptr<ListPositionAllocator> pos = CreateObject<ListPositionAllocator> ();
  std::vector<std::string> rsuLabels;   // RSU_row_col label per node (grid order)
  for (uint32_t r = 0; r < rsuRows; ++r)
    for (uint32_t c = 0; c < rsuCols; ++c)
      {
        pos->Add (Vector (gridX0 + c * rsuSpacing, gridY0 + r * rsuSpacing, 0.0));
        rsuLabels.push_back ("RSU_" + std::to_string (r) + "_" + std::to_string (c));
      }
  rsuMob.SetPositionAllocator (pos);
  rsuMob.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  rsuMob.Install (rsus);

  // ---- NetAnim visualisation ----
  AnimationInterface anim (animFile);
  anim.SetMobilityPollInterval (Seconds (0.5));

  // colour + label vehicles (blue) vs RSUs (red squares)
  for (uint32_t i = 0; i < vehicles.GetN (); ++i)
    {
      anim.UpdateNodeDescription (vehicles.Get (i), "V" + std::to_string (i));
      anim.UpdateNodeColor (vehicles.Get (i), 0, 120, 255);   // blue vehicles
      anim.UpdateNodeSize (vehicles.Get (i)->GetId (), 20, 20);
    }
  for (uint32_t i = 0; i < rsus.GetN (); ++i)
    {
      anim.UpdateNodeDescription (rsus.Get (i), rsuLabels[i]);  // RSU_row_col
      anim.UpdateNodeColor (rsus.Get (i), 30, 170, 30);        // green RSUs
      anim.UpdateNodeSize (rsus.Get (i)->GetId (), 40, 40);
    }

  std::cout << "[galle_netanim] " << nVehicles << " vehicles + " << nRsu
            << " RSUs (" << rsuRows << "x" << rsuCols << " grid, "
            << rsuSpacing << " m spacing)\n"
            << "  grid origin (" << gridX0 << "," << gridY0 << ") -> ["
            << gridX0 << ".." << gridX0 + (rsuCols - 1) * rsuSpacing << "] x ["
            << gridY0 << ".." << gridY0 + (rsuRows - 1) * rsuSpacing << "]\n"
            << "  writing NetAnim XML -> " << animFile << "  (" << duration << " s clip)\n";

  Simulator::Stop (Seconds (duration));
  Simulator::Run ();
  Simulator::Destroy ();
  std::cout << "[galle_netanim] done.\n";
  return 0;
}
