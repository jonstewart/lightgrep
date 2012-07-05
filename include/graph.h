#pragma once

#include "basic.h"

#include <algorithm>
#include <functional>
#include <limits>
#include <vector>

template <class GraphType,
          class VertexType,
          class EdgeType,
          template <typename> class EdgeDescriptorStorage>
class Graph: public GraphType
{
private:
  struct VertexData;
  struct EdgeData;

  typedef typename std::vector<VertexData> VList;
  typedef typename std::vector<EdgeData> EList;

public:
  typedef uint32 VertexDescriptor;
  typedef uint32 EdgeDescriptor;

  typedef typename VList::size_type VertexSizeType;
  typedef typename EList::size_type EdgeSizeType;

  typedef VertexType Vertex;
  typedef EdgeType Edge;

  typedef typename VList::iterator VertexIterator;
  typedef typename VList::const_iterator ConstVertexIterator;
  typedef typename EList::iterator EdgeIterator;
  typedef typename EList::const_iterator ConstEdgeIterator;

private:
#pragma pack(push, 1)
  struct VertexData: public VertexType {
    VertexData(): VertexType() {}

    VertexData(const VertexType& v): VertexType(v) {}

    typename EdgeDescriptorStorage<EdgeDescriptor>::ListType In, Out;
  };
#pragma pack(pop)

  struct EdgeData: public EdgeType {
    EdgeData(VertexDescriptor head, VertexDescriptor tail, const EdgeType& e): EdgeType(e), Head(head), Tail(tail) {}

    VertexDescriptor Head, Tail;
  };

  VList Vertices;
  EList Edges;

  EdgeDescriptorStorage<EdgeDescriptor> Store;

public:
  Graph(VertexSizeType vActual = 0): Vertices(vActual, VertexData()) {}

  Graph(VertexSizeType vActual, VertexSizeType vReserve, EdgeSizeType eReserve = 0) {
    if (vReserve > vActual) {
      Vertices.reserve(vReserve);
    }

    Vertices.resize(vActual, VertexData());
    Edges.reserve(eReserve);
  }

  //
  // lookup & access
  //

  VertexDescriptor inVertex(VertexDescriptor tail, EdgeSizeType i) const {
    return Edges[Store.at(Vertices[tail].In, i)].Head;
  }

  VertexDescriptor outVertex(VertexDescriptor head, EdgeSizeType i) const {
    return Edges[Store.at(Vertices[head].Out, i)].Tail;
  }

  EdgeDescriptor inEdge(VertexDescriptor tail, EdgeSizeType i) const {
    return Store.at(Vertices[tail].In, i);
  }

  EdgeDescriptor outEdge(VertexDescriptor head, EdgeSizeType i) const {
    return Store.at(Vertices[head].Out, i);
  }

  EdgeSizeType inDegree(VertexDescriptor tail) const {
    return Store.size(Vertices[tail].In);
  }

  EdgeSizeType outDegree(VertexDescriptor head) const {
    return Store.size(Vertices[head].Out);
  }

  VertexType& operator[](VertexDescriptor vd) {
    return Vertices[vd];
  }

  const VertexType& operator[](VertexDescriptor vd) const {
    return Vertices[vd];
  }

  EdgeType& operator()(EdgeDescriptor ed) {
    return Edges[ed];
  }

  const EdgeType& operator()(EdgeDescriptor ed) const {
    return Edges[ed];
  }

  //
  // iterators
  //

/*
  VertexIterator vBegin() {
    return Vertices.begin();
  }

  ConstVertexIterator vBegin() const {
    return Vertices.begin();
  };

  VertexIterator vEnd() {
    return Vertices.end();
  }

  ConstVertexIterator vEnd() const {
    return Vertices.end();
  };

  EdgeIterator eBegin() {
    return Edges.begin();
  }

  ConstEdgeIterator eBegin() const {
    return Edges.begin();
  }

  EdgeIterator eEnd() {
    return Edges.end();
  }

  ConstEdgeIterator eEnd() const {
    return Edges.end();
  }

  VertexIterator ivBegin(VertexDescriptor tail) {
    return Store.ivbegin(this);
  }

  ConstVertexIterator ivBegin() const {
    return store.ivbegin(this);
  }

  VertexIterator ivEnd() {
    return store.ivend(this);
  }

  ConstVertexIterator ivEnd() const {
    return store.ivend(this);
  }

  VertexIterator ovBegin() {
    return store.ovbegin(this);
  }

  ConstVertexIterator ovBegin() const {
    return store.ovbegin(this);
  }

  VertexIterator ovEnd() {
    return store.ovend(this);
  }

  ConstVertexIterator ovEnd() const {
    return store.ovend(this);
  }

  EdgeIterator ieBegin() {
    return store.iebegin(this);
  }

  ConstEdgeIterator ieBegin() const {
    return store.iebegin(this);
  }

  EdgeIterator ieEnd() {
    return store.ieend(this);
  }

  ConstEdgeIterator ieEnd() const {
    return store.ieend(this);
  }

  EdgeIterator oeBegin() {
    return store.oebegin(this);
  }

  ConstEdgeIterator oeBegin() const {
    return store.oebegin(this);
  }

  EdgeIterator oeEnd() {
    return store.oeend(this);
  }

  ConstEdgeIterator oeEnd() const {
    return store.oeend(this);
  }
*/

  //
  // modifiers
  //

  void clear() {
    clearVertices();
  }

  void clearEdges() {
    Edges.clear();

    const typename VList::iterator iend(Vertices.end());
    for (typename VList::iterator i(Vertices.begin()); i != iend; ++i) {
      Store.clear(i->In);
      Store.clear(i->Out);
    }
  }

  void clearVertices() {
    Vertices.clear();
    Edges.clear();
  }

  VertexDescriptor addVertex(const VertexType& v = VertexType()) {
    Vertices.emplace_back(v);
    return Vertices.size() - 1;
  }

  void removeVertex(VertexDescriptor vd) {
    using namespace std::placeholders;

    const VertexData& v(Vertices[vd]);
    std::for_each(Store.begin(v.In), Store.end(v.In), std::bind(&Graph::removeEdge, this, _1));
    std::for_each(Store.begin(v.Out), Store.end(v.Out), std::bind(&Graph::removeEdge, this, _1));

    compact_after_vertex(vd);
  }

  EdgeDescriptor addEdge(VertexDescriptor head, VertexDescriptor tail, const EdgeType& e = EdgeType()) {
    Edges.emplace_back(head, tail, e);
    const EdgeDescriptor ed = Edges.size() - 1;
    Store.add(Vertices[head].Out, ed);
    Store.add(Vertices[tail].In, ed);
    return ed;
  }

  EdgeDescriptor insertEdge(VertexDescriptor head, VertexDescriptor tail, EdgeSizeType hi = std::numeric_limits<EdgeSizeType>::max(), EdgeSizeType ti = std::numeric_limits<EdgeSizeType>::max(), const EdgeType& e = EdgeType()) {
    Edges.emplace_back(head, tail, e);
    const EdgeDescriptor ed = Edges.size() - 1;
    Store.insert(Vertices[head].Out, hi, ed);
    Store.insert(Vertices[tail].In, ti, ed);
    return ed;
  }

  void removeEdge(EdgeDescriptor ed) {
    Store.remove(Vertices[Edges[ed].Head].Out, ed);
    Store.remove(Vertices[Edges[ed].Tail].In, ed);
    compact_after_edge(ed);
  }

  //
  // capacity
  //

  VertexSizeType verticesSize() const {
    return Vertices.size();
  }

  EdgeSizeType edgesSize() const {
    return Edges.size();
  }

  VertexSizeType verticesCapacity() const {
    return Vertices.capacity();
  }

  EdgeSizeType edgesCapacity() const {
    return Edges.capacity();
  }

  void reserveVertices(VertexSizeType size) {
    return Vertices.reserve(size);
  }

  void reserveEdges(EdgeSizeType size) {
    return Edges.reserve(size);
  }

private:
  void compact_after_edge(EdgeDescriptor ed) {
    typename EList::iterator i(Edges.erase(Edges.begin() + ed));
    const typename EList::iterator iend(Edges.end());
    for ( ; i != iend; ++i) {
      const EdgeDescriptor e = i - Edges.begin() + 1;
      --*Store.find(Vertices[i->Head].Out, e);
      --*Store.find(Vertices[i->Tail].In, e);
    }
  }

  void compact_after_vertex(VertexDescriptor vd) {
    Vertices.erase(Vertices.begin() + vd);

    const typename EList::iterator iend(Edges.end());
    for (typename EList::iterator i(Edges.begin()); i != iend; ++i) {
      if (i->Head > vd) {
        --i->Head;
      }

      if (i->Tail > vd) {
        --i->Tail;
      }
    }
  }
};

template <class G, class V, class E, template <typename> class S> std::ostream& operator<<(std::ostream& out, const Graph<G,V,E,S>& g) {
  const typename Graph<G,V,E,S>::VertexSizeType vnum = g.verticesSize();

  // print graph size
  out << "|g| = " << vnum << '\n';

  // print out edges for each vertex
  for (typename Graph<G,V,E,S>::VertexSizeType v = 0; v < vnum; ++v) {
    const typename Graph<G,V,E,S>::EdgeSizeType odeg = g.outDegree(v);
    for (typename Graph<G,V,E,S>::EdgeSizeType o = 0; o < odeg; ++o) {
      out << v << " -> " << g.outVertex(v, o) << '\n';
    }
  }

  return out;
}
