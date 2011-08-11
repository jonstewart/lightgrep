#pragma once

#include "basic.h"
#include "graph.h"

#include <map>
#include <set>
#include <stack>

class Compiler {
public:
  typedef std::pair<Graph::vertex, Graph::vertex> StatePair;
  typedef std::pair<Graph::vertex, uint32> EdgePair;

  void mergeIntoFSM(Graph& dst, const Graph& src);

  void labelGuardStates(Graph& g);

  void propagateMatchLabels(Graph& g);
  void removeNonMinimalLabels(Graph& g);
  
  StatePair processChild(const Graph& src, Graph& dst, uint32 si, Graph::vertex srcHead, Graph::vertex dstHead);

private:
  std::map<Graph::vertex, std::vector<Graph::vertex> > Dst2Src;
  std::vector<Graph::vertex> Src2Dst;
  std::stack<EdgePair> Edges;
  std::set<EdgePair> Visited;
  std::map<Graph::vertex,uint32> DstPos;
};
