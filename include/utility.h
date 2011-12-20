#pragma once

#include "basic.h"

#include <string>
#include <vector>

#include "compiler.h"
#include "graph.h"
#include "nfabuilder.h"
#include "vm_interface.h"

struct SearchInfo {

};

enum Encodings {
  CP_ASCII = 1,
  CP_UCS16 = 2
};

GraphPtr createGraph(const std::vector<std::string>& keywords,
                    uint32 enc = CP_ASCII, 
                    bool caseSensitive = true, 
                    bool litMode = false, 
                    bool determinize = true,
                    bool ignoreBadParse = false);

class Visitor {
public:
  virtual void discoverVertex(Graph::vertex,
                              const Graph&) const {}

  virtual void treeEdge(Graph::vertex,
                        Graph::vertex,
                        const Graph&) const {}
};

void bfs(const Graph& graph, Graph::vertex start, Visitor& visitor);

uint32 calculateLMin(const Graph& graph);

boost::shared_ptr<SkipTable> calculateSkipTable(const Graph& graph);

ProgramPtr createProgram(const Graph& graph);

ByteSet firstBytes(const Graph& graph);
void nextBytes(ByteSet& set, Graph::vertex v, const Graph& graph);

boost::shared_ptr<VmInterface> initVM(const std::vector<std::string>& keywords, SearchInfo& info);

std::vector< std::vector< Graph::vertex > > pivotStates(Graph::vertex source, const Graph& graph);

uint32 maxOutbound(const std::vector< std::vector< Graph::vertex > >& tranTable);

void writeGraphviz(std::ostream& out, const Graph& graph);
